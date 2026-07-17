package burpsuite;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;

import java.util.concurrent.ExecutorService;

public class WebsocketCreatedHandler implements ProxyWebSocketCreationHandler {

    private final MontoyaApi api;
    private final MyTableModel table;
    private final ExecutorService scanExecutor;

    public WebsocketCreatedHandler(MyTableModel table, MontoyaApi api, ExecutorService scanExecutor) {
        this.api = api;
        this.table = table;
        this.scanExecutor = scanExecutor;
    }

    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation webSocketCreation) {
        webSocketCreation.proxyWebSocket().registerProxyMessageHandler(
                new WebsocketMessageHandler(table, api, webSocketCreation, scanExecutor)
        );
    }
}