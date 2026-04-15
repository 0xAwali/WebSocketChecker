package burpsuite;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import javax.swing.table.AbstractTableModel;
import java.util.*;

public class MyTableModel extends AbstractTableModel {

    private final MontoyaApi api;
    private final List<LogEntry> log;
    private static class LogEntry {
        private final ProxyWebSocketCreation webSocketCreated;
        private final Object message;
        private final String information;


        public LogEntry(ProxyWebSocketCreation webSocketCreated, Object message,String information) {
            this.webSocketCreated = webSocketCreated;
            this.message = message;
            this.information = information;
        }

        public ProxyWebSocketCreation getWebSocketCreated() {
            return webSocketCreated;
        }

        public Object getMessage() {
            return message;
        }

        public String getInformation() {
            return information;
        }

        public boolean isBinaryMessage() {
            return message instanceof InterceptedBinaryMessage;
        }

        public boolean isTextMessage() {
            return message instanceof InterceptedTextMessage;
        }
    }

    public MyTableModel(MontoyaApi api) {
        this.api = api;
        this.log = new ArrayList<>(); // Initialize the list
    }

    @Override
    public synchronized int getRowCount() {
        return log.size(); // Return the size of the list
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public String getColumnName(int column) {
        return switch (column) {
            case 0 -> "#";
            case 1 -> "Host";
            case 2 -> "Path";
            case 3 -> "Information";
            default -> "";
        };
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry entry = log.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return rowIndex + 1; // Row number
            case 1:
                return entry.getWebSocketCreated().upgradeRequest().headerValue("Host"); // URL (String)
            case 2:
                return entry.getWebSocketCreated().upgradeRequest().pathWithoutQuery();
            case 3:
                if (!entry.getInformation().isEmpty()){
                    return entry.getInformation();
                }else {
                    return "";
                }
            default:
                return "";
        }
    }

    public synchronized void add(ProxyWebSocketCreation webSocketCreated, Object message,String information) {
        if (!(message instanceof InterceptedBinaryMessage) && !(message instanceof InterceptedTextMessage)) {
            throw new IllegalArgumentException("Message must be either InterceptedBinaryMessage or InterceptedTextMessage");
        }

        LogEntry entry = new LogEntry(webSocketCreated, message, information); // Create a new LogEntry
        log.add(entry);
        int index = log.size() - 1;
        fireTableRowsInserted(index, index);
    }

    public synchronized Object get(int rowIndex) {
        LogEntry entry = log.get(rowIndex);
        return entry.getMessage();
    }
}