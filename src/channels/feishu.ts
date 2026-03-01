import crypto from 'node:crypto';
import { createServer, IncomingMessage, ServerResponse } from 'node:http';

import axios, { AxiosError } from 'axios';

import { ASSISTANT_NAME } from '../config.js';
import { logger } from '../logger.js';

/**
 * Decrypt Feishu encrypted event payload
 * Uses AES-256-CBC with SHA256 key derivation
 * Reference: https://open.feishu.cn/document/event-subscription-guide/event-subscriptions/event-subscription-configure-/choose-a-subscription-mode/send-notifications-to-developers-server
 */
function decryptFeishuPayload(
  encryptKey: string,
  encryptedData: string,
): string {
  // Decode base64
  const encryptBuffer = Buffer.from(encryptedData, 'base64');

  // Derive key using SHA256
  const key = crypto.createHash('sha256').update(encryptKey).digest();

  // Decrypt using AES-256-CBC (Node.js handles PKCS7 padding automatically)
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    key,
    encryptBuffer.slice(0, 16),
  );
  let decrypted = decipher.update(
    encryptBuffer.slice(16).toString('hex'),
    'hex',
    'utf8',
  );
  decrypted += decipher.final('utf8');

  return decrypted;
}
import {
  Channel,
  OnInboundMessage,
  OnChatMetadata,
  RegisteredGroup,
} from '../types.js';

export interface FeishuChannelOpts {
  onMessage: OnInboundMessage;
  onChatMetadata: OnChatMetadata;
  registeredGroups: () => Record<string, RegisteredGroup>;
  appId: string;
  appSecret: string;
  encryptKey?: string;
  port?: number;
}

interface FeishuMessage {
  message_id: string;
  chat_id: string;
  chat_type: string;
  message_type: string;
  content: string;
  create_time: string;
  sender: {
    sender_id: {
      open_id: string;
    };
    sender_type: string;
  };
}

export class FeishuChannel implements Channel {
  name = 'feishu';

  private server: ReturnType<typeof createServer> | null = null;
  private connected = false;
  private opts: FeishuChannelOpts;
  private port: number;
  private appId: string;
  private appSecret: string;
  private encryptKey?: string;
  private tenantAccessToken: string | null = null;
  private tokenExpireTime = 0;
  private outgoingQueue: Array<{ chatId: string; text: string }> = [];
  private flushing = false;
  // Map internal JIDs to original Feishu chat IDs for replies
  private jidToChatId: Map<string, string> = new Map();

  constructor(opts: FeishuChannelOpts) {
    this.opts = opts;
    this.port = opts.port ?? 3000;
    this.appId = opts.appId;
    this.appSecret = opts.appSecret;
    this.encryptKey = opts.encryptKey;

    if (!this.appId || !this.appSecret) {
      throw new Error('FEISHU_APP_ID and FEISHU_APP_SECRET must be set');
    }
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createServer((req: IncomingMessage, res: ServerResponse) =>
        this.handleRequest(req, res),
      );

      this.server.listen(this.port, '0.0.0.0', () => {
        this.connected = true;
        logger.info({ port: this.port }, 'Feishu webhook server started');
        resolve();
      });

      this.server.on('error', (err: Error) => {
        logger.error({ err }, 'Feishu server error');
        reject(err);
      });
    });
  }

  private async handleRequest(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    logger.info(
      { method: req.method, url: req.url },
      'Feishu webhook request received',
    );

    if (req.method !== 'POST' || req.url !== '/webhook') {
      logger.warn(
        { method: req.method, url: req.url },
        'Feishu webhook invalid request',
      );
      res.statusCode = 404;
      res.end();
      return;
    }

    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });

    req.on('end', async () => {
      logger.info({ bodyLength: body.length }, 'Feishu webhook body received');
      try {
        // Verify signature if encrypt key is set and headers are present
        if (this.encryptKey) {
          const signature = req.headers['x-lark-signature'] as string;
          const timestamp = req.headers['x-lark-request-timestamp'] as string;
          const nonce = req.headers['x-lark-request-nonce'] as string;

          logger.info(
            {
              hasSignature: !!signature,
              hasTimestamp: !!timestamp,
              hasNonce: !!nonce,
            },
            'Feishu signature headers',
          );

          // Only verify if headers are present (Feishu sends them when encrypt key is configured)
          if (signature && timestamp && nonce) {
            if (!this.verifySignature(body, signature, timestamp, nonce)) {
              logger.warn('Feishu signature verification failed');
              res.statusCode = 401;
              res.end(JSON.stringify({ code: 401, msg: 'Invalid signature' }));
              return;
            }
            logger.info('Feishu signature verified');
          } else {
            logger.info(
              'Feishu signature headers missing, skipping verification',
            );
          }
        }

        let rawData;
        try {
          rawData = JSON.parse(body);
        } catch (parseErr) {
          logger.error(
            { err: parseErr, bodyPreview: body.slice(0, 200) },
            'Feishu JSON parse failed',
          );
          res.statusCode = 400;
          res.end(JSON.stringify({ code: 400, msg: 'Invalid JSON' }));
          return;
        }

        // Decrypt payload if encrypted
        let data = rawData;
        if (rawData.encrypt && this.encryptKey) {
          try {
            const decryptedBody = decryptFeishuPayload(
              this.encryptKey,
              rawData.encrypt,
            );
            data = JSON.parse(decryptedBody);
            logger.info(
              { decryptedType: data.type },
              'Feishu payload decrypted',
            );
          } catch (decryptErr) {
            logger.error(
              { err: decryptErr },
              'Feishu payload decryption failed',
            );
            res.statusCode = 400;
            res.end(JSON.stringify({ code: 400, msg: 'Decryption failed' }));
            return;
          }
        }

        logger.info(
          {
            type: data.type,
            hasEvent: !!data.event,
            hasEncrypt: !!rawData.encrypt,
          },
          'Feishu webhook data parsed',
        );

        // URL verification challenge
        if (data.type === 'url_verification') {
          logger.info(
            { challenge: data.challenge },
            'Feishu URL verification challenge received',
          );
          const response = { challenge: data.challenge };
          const responseBody = JSON.stringify(response);
          logger.info({ responseBody }, 'Feishu URL verification response');

          res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Length': Buffer.byteLength(responseBody),
          });
          res.write(responseBody);
          res.end();
          logger.info('Feishu URL verification challenge responded');
          return;
        }

        // Handle message events
        logger.info(
          {
            eventType: data.type,
            hasMessage: !!data.event?.message,
            messageType: data.event?.message?.message_type,
            chatId: data.event?.message?.chat_id,
          },
          'Feishu event structure',
        );

        if (data.event?.message?.message_type === 'text') {
          await this.handleMessage(data.event.message);
        } else if (data.event) {
          logger.info(
            { eventKeys: Object.keys(data.event) },
            'Feishu unhandled event type',
          );
        }

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ code: 0, msg: 'success' }));
      } catch (err) {
        logger.error({ err }, 'Feishu webhook error');
        res.statusCode = 500;
        res.end(JSON.stringify({ code: 500, msg: 'Internal error' }));
      }
    });
  }

  private verifySignature(
    body: string,
    signature: string,
    timestamp: string,
    nonce: string,
  ): boolean {
    const signString = `${timestamp}${nonce}${this.encryptKey}${body}`;
    const hash = crypto.createHash('sha256').update(signString).digest('hex');
    return hash === signature;
  }

  private async handleMessage(msg: FeishuMessage): Promise<void> {
    const chatId = msg.chat_id;
    const content = JSON.parse(msg.content);
    const text = content.text?.trim() || '';
    const senderId = msg.sender?.sender_id?.open_id || '';
    const timestamp = new Date(parseInt(msg.create_time)).toISOString();

    // Route to main group if chat not registered
    const groups = this.opts.registeredGroups();
    let targetChatId = chatId;
    let targetIsGroup = msg.chat_type === 'group';

    if (!groups[chatId]) {
      // Find main group JID
      const mainEntry = Object.entries(groups).find(
        ([_, g]) => g.folder === 'main',
      );
      if (mainEntry) {
        targetChatId = mainEntry[0];
        targetIsGroup = true; // Main group is always a group
        // Store mapping so we can reply to the correct Feishu chat
        this.jidToChatId.set(targetChatId, chatId);
        logger.info(
          { chatId, targetChatId },
          'Routing Feishu message to main group',
        );
      } else {
        logger.info(
          { chatId, registeredGroups: Object.keys(groups).length },
          'Feishu message skipped - no main group available',
        );
        return;
      }
    }

    // Always notify about chat metadata for the target chat
    this.opts.onChatMetadata(
      targetChatId,
      timestamp,
      undefined,
      'feishu',
      targetIsGroup,
    );

    // Skip empty messages
    if (!text) {
      return;
    }

    // Detect bot messages (messages from ourselves)
    const isBotMessage = text.startsWith(`${ASSISTANT_NAME}:`);

    logger.info(
      { chatId, sender: senderId, text: text.slice(0, 100) },
      'Feishu message received',
    );

    this.opts.onMessage(targetChatId, {
      id: msg.message_id,
      chat_jid: targetChatId,
      sender: senderId,
      sender_name: senderId.slice(0, 8), // Use first 8 chars of open_id as name
      content: `[Feishu ${chatId.slice(-8)}] ${text}`,
      timestamp,
      is_from_me: false,
      is_bot_message: isBotMessage,
    });
  }

  private async getTenantAccessToken(): Promise<string> {
    if (this.tenantAccessToken && Date.now() < this.tokenExpireTime) {
      return this.tenantAccessToken;
    }

    try {
      const response = await axios.post(
        'https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal',
        {
          app_id: this.appId,
          app_secret: this.appSecret,
        },
      );

      if (response.data.code !== 0) {
        throw new Error(`Failed to get token: ${response.data.msg}`);
      }

      this.tenantAccessToken = response.data.tenant_access_token;
      // Refresh 60 seconds before expiry
      this.tokenExpireTime = Date.now() + (response.data.expire - 60) * 1000;
      return this.tenantAccessToken!;
    } catch (err) {
      logger.error({ err }, 'Failed to get Feishu access token');
      throw err;
    }
  }

  async sendMessage(jid: string, text: string): Promise<void> {
    // Prefix bot messages with assistant name
    const prefixed = `${ASSISTANT_NAME}: ${text}`;

    if (!this.connected) {
      this.outgoingQueue.push({ chatId: jid, text: prefixed });
      logger.info(
        { jid, queueSize: this.outgoingQueue.length },
        'Feishu disconnected, message queued',
      );
      return;
    }

    try {
      const token = await this.getTenantAccessToken();
      
      // Map internal JID back to original Feishu chat ID if needed
      const actualChatId = this.jidToChatId.get(jid) || jid;

      await axios.post(
        'https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id',
        {
          receive_id: actualChatId,
          msg_type: 'text',
          content: JSON.stringify({ text: prefixed }),
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        },
      );

      logger.info({ jid, actualChatId, length: prefixed.length }, 'Feishu message sent');
    } catch (err) {
      // Queue for retry
      this.outgoingQueue.push({ chatId: jid, text: prefixed });
      logger.warn(
        { jid, err, queueSize: this.outgoingQueue.length },
        'Failed to send Feishu message, queued',
      );
    }
  }

  async sendImage(jid: string, imageBuffer: Buffer): Promise<void> {
    try {
      const token = await this.getTenantAccessToken();
      
      // Map internal JID back to original Feishu chat ID if needed
      const actualChatId = this.jidToChatId.get(jid) || jid;

      // Upload image first
      const FormData = (await import('form-data')).default;
      const form = new FormData();
      form.append('image_type', 'message');
      form.append('image', imageBuffer, {
        filename: 'screenshot.png',
        contentType: 'image/png',
      });

      const uploadRes = await axios.post(
        'https://open.feishu.cn/open-apis/im/v1/images',
        form,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            ...form.getHeaders(),
          },
        },
      );

      if (uploadRes.data.code !== 0) {
        throw new Error(`Failed to upload image: ${uploadRes.data.msg}`);
      }

      const imageKey = uploadRes.data.data.image_key;

      // Send image message
      await axios.post(
        'https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id',
        {
          receive_id: actualChatId,
          msg_type: 'image',
          content: JSON.stringify({ image_key: imageKey }),
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        },
      );

      logger.info({ jid, actualChatId }, 'Feishu image sent');
    } catch (err) {
      logger.error({ jid, err }, 'Failed to send Feishu image');
    }
  }

  isConnected(): boolean {
    return this.connected;
  }

  ownsJid(jid: string): boolean {
    // Feishu chat IDs are opaque strings (open_chat_id format)
    return !jid.includes('@');
  }

  async disconnect(): Promise<void> {
    this.connected = false;
    if (this.server) {
      return new Promise((resolve) => {
        this.server?.close(() => {
          logger.info('Feishu server stopped');
          resolve();
        });
      });
    }
  }

  // Feishu doesn't have typing indicators in the same way
  async setTyping(_jid: string, _isTyping: boolean): Promise<void> {
    // No-op for Feishu
  }

  private async flushOutgoingQueue(): Promise<void> {
    if (this.flushing || this.outgoingQueue.length === 0) return;
    this.flushing = true;

    try {
      logger.info(
        { count: this.outgoingQueue.length },
        'Flushing Feishu outgoing queue',
      );

      while (this.outgoingQueue.length > 0) {
        const item = this.outgoingQueue.shift()!;
        await this.sendMessage(
          item.chatId,
          item.text.replace(`${ASSISTANT_NAME}: `, ''),
        );
      }
    } finally {
      this.flushing = false;
    }
  }
}
