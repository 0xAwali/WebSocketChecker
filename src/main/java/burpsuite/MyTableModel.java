package burpsuite;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class MyTableModel extends AbstractTableModel {

    private final MontoyaApi api;
    // Guarded by 'this' for cross-thread reads; mutations dispatched to the EDT.
    private final List<LogEntry> log = new ArrayList<>();

    // ── Inner record ─────────────────────────────────────────────────────────

    private static final class LogEntry {
        final ProxyWebSocketCreation webSocketCreated;
        final Object                 message;   // InterceptedTextMessage or InterceptedBinaryMessage
        final String                 information;

        LogEntry(ProxyWebSocketCreation webSocketCreated, Object message, String information) {
            this.webSocketCreated = webSocketCreated;
            this.message          = message;
            this.information      = information;
        }
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    public MyTableModel(MontoyaApi api) {
        this.api = api;
    }

    // ── AbstractTableModel ────────────────────────────────────────────────────

    @Override
    public synchronized int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public String getColumnName(int column) {
        return switch (column) {
            case 0  -> "#";
            case 1  -> "Host";
            case 2  -> "Path";
            case 3  -> "Information";
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        // Allows the '#' sorter to treat the value as an Integer automatically.
        return columnIndex == 0 ? Integer.class : String.class;
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry entry = log.get(rowIndex);
        return switch (columnIndex) {
            case 0  -> rowIndex + 1;
            case 1  -> entry.webSocketCreated.upgradeRequest().headerValue("Host");
            case 2  -> entry.webSocketCreated.upgradeRequest().pathWithoutQuery();
            case 3  -> entry.information;
            default -> "";
        };
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Adds a new row to the table.  Safe to call from any thread — the Swing
     * notification is always dispatched on the Event Dispatch Thread.
     */
    public void add(ProxyWebSocketCreation webSocketCreated, Object message, String information) {
        if (!(message instanceof InterceptedTextMessage)
                && !(message instanceof InterceptedBinaryMessage)) {
            throw new IllegalArgumentException(
                    "message must be InterceptedTextMessage or InterceptedBinaryMessage");
        }

        final int insertedIndex;
        synchronized (this) {
            log.add(new LogEntry(webSocketCreated, message, information));
            insertedIndex = log.size() - 1;
        }

        // fireTableRowsInserted must be called on the EDT.
        if (SwingUtilities.isEventDispatchThread()) {
            fireTableRowsInserted(insertedIndex, insertedIndex);
        } else {
            SwingUtilities.invokeLater(() -> fireTableRowsInserted(insertedIndex, insertedIndex));
        }
    }

    /**
     * Returns the raw message object at the given model row index.
     * Used by the selection listener to populate the message viewer.
     */
    public synchronized Object get(int rowIndex) {
        return log.get(rowIndex).message;
    }
}