package burpsuite;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.regex.Pattern;

public class WebsocketMessageHandler implements ProxyMessageHandler {

    private static final long SCAN_TIMEOUT_SECONDS = 5;

    private final MontoyaApi api;
    private final MyTableModel table;
    private final ProxyWebSocketCreation webSocketCreated;
    private final ExecutorService scanExecutor;

    public WebsocketMessageHandler(MyTableModel table, MontoyaApi api, ProxyWebSocketCreation webSocketCreated, ExecutorService scanExecutor) {
        this.api = api;
        this.table = table;
        this.webSocketCreated = webSocketCreated;
        this.scanExecutor = scanExecutor;
    }

    @Override
    public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage interceptedTextMessage) {
        // Scan both directions: credentials can appear in client-originated
        // frames (API calls, subscription payloads) as well as server responses.
        String matchedKeys = scanMessageForSensitiveData(interceptedTextMessage.payload());
        if (!matchedKeys.isEmpty()) {
            table.add(webSocketCreated, interceptedTextMessage, interceptedTextMessage.direction(), matchedKeys);
        }
        return TextMessageReceivedAction.continueWith(interceptedTextMessage);
    }

    @Override
    public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage interceptedTextMessage) {
        return TextMessageToBeSentAction.continueWith(interceptedTextMessage);
    }

    @Override
    public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage interceptedBinaryMessage) {
        // Decode explicitly as UTF-8 rather than relying on ByteArray#toString(),
        // whose output format isn't guaranteed to be a faithful UTF-8 decode.
        String payloadText = new String(interceptedBinaryMessage.payload().getBytes(), StandardCharsets.UTF_8);
        String matchedKeys = scanMessageForSensitiveData(payloadText);
        if (!matchedKeys.isEmpty()) {
            table.add(webSocketCreated, interceptedBinaryMessage, interceptedBinaryMessage.direction(), matchedKeys);
        }
        return BinaryMessageReceivedAction.continueWith(interceptedBinaryMessage);
    }

    @Override
    public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage interceptedBinaryMessage) {
        return BinaryMessageToBeSentAction.continueWith(interceptedBinaryMessage);
    }

    private String scanMessageForSensitiveData(String messageContent) {
        Map<String, Pattern> patterns = ConcurrentRegexSearch.getCompiledPatterns();
        List<Future<Map.Entry<String, List<String>>>> futures = new ArrayList<>(patterns.size());

        // Submits to the extension-wide shared pool instead of spinning up a new
        // ~100-thread pool per message.
        for (Map.Entry<String, Pattern> entry : patterns.entrySet()) {
            futures.add(scanExecutor.submit(new ConcurrentRegexSearch.RegexSearchTask(entry.getKey(), entry.getValue(), messageContent)));
        }

        StringBuilder matchedKeys = new StringBuilder();
        for (Future<Map.Entry<String, List<String>>> future : futures) {
            try {
                Map.Entry<String, List<String>> result = future.get(SCAN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                if (!result.getValue().isEmpty()) {
                    if (matchedKeys.length() > 0) {
                        matchedKeys.append(" , ");
                    }
                    matchedKeys.append(result.getKey());
                }
            } catch (TimeoutException e) {
                future.cancel(true);
                api.logging().logToError("Regex scan timed out for one pattern; skipping.");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                api.logging().logToError("Regex scan interrupted: " + e.getMessage());
                break;
            } catch (ExecutionException e) {
                api.logging().logToError("Error scanning message for sensitive data: " + e.getMessage());
            }
        }

        return matchedKeys.toString();
    }
}