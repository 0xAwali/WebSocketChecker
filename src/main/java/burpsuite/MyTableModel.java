package burpsuite;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.websocket.Direction;

import javax.swing.table.AbstractTableModel;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class MyTableModel extends AbstractTableModel {

    private final MontoyaApi api;
    private final List<LogEntry> log;

    private static class LogEntry {
        private final ProxyWebSocketCreation webSocketCreated;
        private final Object message;
        private final Direction direction;
        private final String information;

        public LogEntry(ProxyWebSocketCreation webSocketCreated, Object message, Direction direction, String information) {
            this.webSocketCreated = webSocketCreated;
            this.message = message;
            this.direction = direction;
            this.information = information;
        }

        public ProxyWebSocketCreation getWebSocketCreated() {
            return webSocketCreated;
        }

        public Object getMessage() {
            return message;
        }

        public Direction getDirection() {
            return direction;
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

        /** Decoded, human-readable payload used for CSV export. */
        public String getPayloadText() {
            if (message instanceof InterceptedTextMessage textMessage) {
                return textMessage.payload();
            } else if (message instanceof InterceptedBinaryMessage binaryMessage) {
                return new String(binaryMessage.payload().getBytes(), StandardCharsets.UTF_8);
            }
            return "";
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
        return 5;
    }

    @Override
    public String getColumnName(int column) {
        return switch (column) {
            case 0 -> "#";
            case 1 -> "Host";
            case 2 -> "Path";
            case 3 -> "Direction";
            case 4 -> "Information";
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
                return entry.getDirection() == Direction.CLIENT_TO_SERVER ? "Client -> Server" : "Server -> Client";
            case 4:
                if (!entry.getInformation().isEmpty()) {
                    return entry.getInformation();
                } else {
                    return "";
                }
            default:
                return "";
        }
    }

    public synchronized void add(ProxyWebSocketCreation webSocketCreated, Object message, Direction direction, String information) {
        if (!(message instanceof InterceptedBinaryMessage) && !(message instanceof InterceptedTextMessage)) {
            throw new IllegalArgumentException("Message must be either InterceptedBinaryMessage or InterceptedTextMessage");
        }

        LogEntry entry = new LogEntry(webSocketCreated, message, direction, information); // Create a new LogEntry
        log.add(entry);
        int index = log.size() - 1;
        fireTableRowsInserted(index, index);
    }

    public synchronized Object get(int rowIndex) {
        LogEntry entry = log.get(rowIndex);
        return entry.getMessage();
    }

    public synchronized void clear() {
        int size = log.size();
        if (size == 0) {
            return;
        }
        log.clear();
        fireTableRowsDeleted(0, size - 1);
    }

    public synchronized List<String[]> exportRows() {
        List<String[]> rows = new ArrayList<>();
        rows.add(new String[]{"#", "Host", "Path", "Direction", "Information", "Payload"});
        for (int i = 0; i < log.size(); i++) {
            LogEntry entry = log.get(i);
            rows.add(new String[]{
                    String.valueOf(i + 1),
                    entry.getWebSocketCreated().upgradeRequest().headerValue("Host"),
                    entry.getWebSocketCreated().upgradeRequest().pathWithoutQuery(),
                    entry.getDirection() == Direction.CLIENT_TO_SERVER ? "Client -> Server" : "Server -> Client",
                    entry.getInformation() == null ? "" : entry.getInformation(),
                    entry.getPayloadText()
            });
        }
        return rows;
    }
}