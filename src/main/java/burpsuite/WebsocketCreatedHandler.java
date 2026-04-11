package burpsuite;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;

import java.util.concurrent.ExecutorService;

public class WebsocketCreatedHandler implements ProxyWebSocketCreationHandler {

    private final MontoyaApi api;
    private final MyTableModel table;
    // Shared executor supplied by the extension entry point.
    private final ExecutorService executor;

    public WebsocketCreatedHandler(MyTableModel table, MontoyaApi api, ExecutorService executor) {
        this.api      = api;
        this.table    = table;
        this.executor = executor;
    }

    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation webSocketCreation) {
        webSocketCreation.proxyWebSocket().registerProxyMessageHandler(
                new WebsocketMessageHandler(table, api, webSocketCreation, executor));
    }
}