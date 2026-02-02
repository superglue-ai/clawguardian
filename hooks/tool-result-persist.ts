/**
 * tool_result_persist hook: redact or block secrets from tool results before persistence.
 * This hook is synchronous; do not return a Promise.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { ClawGuardConfig } from "../config.js";
import { detectSecret } from "../utils/matcher.js";
import { redactText } from "../utils/redact.js";

type ContentBlock = { type: string; text?: string; [key: string]: unknown };

function isTextBlock(block: ContentBlock): block is { type: "text"; text: string } {
  return block.type === "text" && typeof block.text === "string";
}

export function registerToolResultPersistHook(api: OpenClawPluginApi, cfg: ClawGuardConfig): void {
  if (!cfg.filterToolOutputs) {
    return;
  }

  api.on(
    "tool_result_persist",
    (event, _ctx) => {
      const msg = event.message;

      if (!msg.content || !Array.isArray(msg.content)) {
        return;
      }

      // First pass: check if any block contains a secret that should be blocked
      for (const block of msg.content) {
        if (isTextBlock(block)) {
          const result = detectSecret(block.text, cfg);
          if (result && result.action === "block") {
            // Log the detection
            if (cfg.logging.logDetections) {
              api.logger.warn(
                `ClawGuard: Blocking tool output - ${result.match.type} (${result.match.severity}) detected`,
              );
            }
            // Replace entire content with blocked message
            return {
              message: {
                ...msg,
                content: [
                  {
                    type: "text",
                    text: `[ClawGuard: Output blocked - ${result.match.type} detected]`,
                  },
                ],
              },
            };
          }
        }
      }

      // Second pass: redact secrets that should be redacted
      const content = msg.content.map((block: ContentBlock) => {
        if (isTextBlock(block)) {
          return {
            ...block,
            text: redactText(block.text, cfg),
          };
        }
        return block;
      });

      return {
        message: {
          ...msg,
          content,
        },
      };
    },
    { priority: 100 },
  );
}
