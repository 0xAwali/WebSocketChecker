package burpsuite;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.*;
import burp.api.montoya.websocket.Direction;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

public class WebsocketMessageHandler implements ProxyMessageHandler {

    private final MontoyaApi api;
    private final MyTableModel table;
    private final ProxyWebSocketCreation webSocketCreated;
    // BUG FIX: executor is now shared and injected rather than created per-message,
    // which previously caused a severe thread-pool resource leak.
    private final ExecutorService executor;

    public WebsocketMessageHandler(MyTableModel table,
                                   MontoyaApi api,
                                   ProxyWebSocketCreation webSocketCreated,
                                   ExecutorService executor) {
        this.api              = api;
        this.table            = table;
        this.webSocketCreated = webSocketCreated;
        this.executor         = executor;
    }

    // ── Incoming text (server → client) ──────────────────────────────────────

    @Override
    public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage message) {
        if (message.direction() == Direction.SERVER_TO_CLIENT) {
            String matched = scanForSensitiveData(message.payload());
            if (!matched.isEmpty()) {
                table.add(webSocketCreated, message, matched);
            }
        }
        return TextMessageReceivedAction.continueWith(message);
    }

    // ── Outgoing text (client → server) — pass through unchanged ─────────────

    @Override
    public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage message) {
        return TextMessageToBeSentAction.continueWith(message);
    }

    // ── Incoming binary (server → client) ────────────────────────────────────

    @Override
    public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage message) {
        if (message.direction() == Direction.SERVER_TO_CLIENT) {
            // BUG FIX: payload().toString() returned the object reference, not the content.
            // Decode the raw bytes as UTF-8 so regex patterns can match properly.
            String text = new String(message.payload().getBytes(), StandardCharsets.UTF_8);
            String matched = scanForSensitiveData(text);
            if (!matched.isEmpty()) {
                table.add(webSocketCreated, message, matched);
            }
        }
        return BinaryMessageReceivedAction.continueWith(message);
    }

    // ── Outgoing binary (client → server) — pass through unchanged ───────────

    @Override
    public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage message) {
        return BinaryMessageToBeSentAction.continueWith(message);
    }

    // ── Scanning logic ────────────────────────────────────────────────────────

    /**
     * Submits one task per regex pattern to the shared executor and collects
     * the names of every pattern that produced at least one match.
     *
     * @param content the decoded message text to scan
     * @return comma-separated pattern names, or an empty string if nothing matched
     */
    private String scanForSensitiveData(String content) {
        Map<String, Pattern> patterns = ConcurrentRegexSearch.getPatternMap();

        List<Future<Map.Entry<String, List<String>>>> futures = new ArrayList<>(patterns.size());
        for (Map.Entry<String, Pattern> entry : patterns.entrySet()) {
            futures.add(executor.submit(
                    new ConcurrentRegexSearch.RegexSearchTask(entry.getKey(), entry.getValue(), content)));
        }

        StringBuilder matched = new StringBuilder();
        for (Future<Map.Entry<String, List<String>>> future : futures) {
            try {
                Map.Entry<String, List<String>> result = future.get();
                if (!result.getValue().isEmpty()) {
                    if (matched.length() > 0) matched.append(" , ");
                    matched.append(result.getKey());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                api.logging().logToError("Scan interrupted: " + e.getMessage());
            } catch (ExecutionException e) {
                api.logging().logToError("Scan error: " + e.getCause().getMessage());
            }
        }
        return matched.toString();
    }
}