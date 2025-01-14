package burpsuite;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.*;
import burp.api.montoya.websocket.Direction;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class WebsocketMessageHandler implements ProxyMessageHandler {

    MontoyaApi api;
    private final MyTableModel table;
    private final ProxyWebSocketCreation webSocketCreated;

    public WebsocketMessageHandler(MyTableModel table, MontoyaApi api, ProxyWebSocketCreation webSocketCreated) {
        this.api = api;
        this.table = table;
        this.webSocketCreated = webSocketCreated;
    }

    @Override
    public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage interceptedTextMessage) {
            if (interceptedTextMessage.direction().equals(Direction.SERVER_TO_CLIENT)) {
                String matchedKeys = scanMessageForSensitiveData(interceptedTextMessage.payload());
                if (!matchedKeys.isEmpty()) {
                    table.add(webSocketCreated, interceptedTextMessage,matchedKeys);
                    return TextMessageReceivedAction.continueWith(interceptedTextMessage);
                }
            }
        return TextMessageReceivedAction.continueWith(interceptedTextMessage);
    }

    @Override
    public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage interceptedTextMessage) {
        return TextMessageToBeSentAction.continueWith(interceptedTextMessage);
    }

    @Override
    public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage interceptedBinaryMessage) {
            if (interceptedBinaryMessage.direction().equals(Direction.SERVER_TO_CLIENT)) {
                String matchedKeys = scanMessageForSensitiveData(interceptedBinaryMessage.payload().toString());
                if (!matchedKeys.isEmpty()) {
                    table.add(webSocketCreated, interceptedBinaryMessage,matchedKeys);
                    return BinaryMessageReceivedAction.continueWith(interceptedBinaryMessage);
                }
            }

        return BinaryMessageReceivedAction.continueWith(interceptedBinaryMessage);
    }

    @Override
    public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage interceptedBinaryMessage) {
        return BinaryMessageToBeSentAction.continueWith(interceptedBinaryMessage);
    }


    private String scanMessageForSensitiveData(String messageContent) {
        int poolSize = ConcurrentRegexSearch.getRegexMap().size();
        ExecutorService executor = Executors.newFixedThreadPool(poolSize);
        List<Future<Map.Entry<String, List<String>>>> futures = new ArrayList<>();
        for (Map.Entry<String, String> entry : ConcurrentRegexSearch.getRegexMap().entrySet()) {
            futures.add(executor.submit(new ConcurrentRegexSearch.RegexSearchTask(entry.getKey(), entry.getValue(), messageContent)));
        }
        executor.shutdown();
        StringBuilder matchedKeys = new StringBuilder();

        try {
            for (Future<Map.Entry<String, List<String>>> future : futures) {
                Map.Entry<String, List<String>> result = future.get();
                if (!result.getValue().isEmpty()) {
                    if (matchedKeys.length() > 0) {
                        matchedKeys.append(" , ");
                    }
                    matchedKeys.append(result.getKey());
                }
            }
        } catch (InterruptedException | ExecutionException e) {
            api.logging().logToError("Error scanning message for sensitive data: " + e.getMessage());
            return "Error: " + e.getMessage();
        }

        return matchedKeys.toString();
    }


}
