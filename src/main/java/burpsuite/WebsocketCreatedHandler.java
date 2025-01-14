package burpsuite;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;

public class WebsocketCreatedHandler implements ProxyWebSocketCreationHandler {

    MontoyaApi api;
    private final MyTableModel table;
    public WebsocketCreatedHandler(MyTableModel table, MontoyaApi api) {
        this.api = api;
        this.table = table;
    }

    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation webSocketCreation) {
        webSocketCreation.proxyWebSocket().registerProxyMessageHandler(new WebsocketMessageHandler(table,api,webSocketCreation));
    }
}
