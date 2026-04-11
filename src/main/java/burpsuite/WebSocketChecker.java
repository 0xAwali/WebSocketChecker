package burpsuite;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.WebSocketMessageEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.Comparator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

public class WebSocketChecker implements BurpExtension {

    private MontoyaApi api;
    // Shared, bounded thread pool reused across ALL message handlers.
    // Sized to the number of available processors; keeps CPU usage reasonable
    // without the massive overhead of ~100 threads per scanned message.
    private ExecutorService executor;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api      = montoyaApi;
        // Cap at 16 threads — plenty for parallel regex scanning.
        int poolSize  = Math.min(Runtime.getRuntime().availableProcessors() * 2, 16);
        this.executor = Executors.newFixedThreadPool(poolSize);

        MyTableModel table = new MyTableModel(api);

        api.extension().setName("WebSocket Checker");
        api.userInterface().registerSuiteTab("WebSocket Checker", buildLoggerTab(table));
        api.proxy().registerWebSocketCreationHandler(
                new WebsocketCreatedHandler(table, api, executor));

        // Shut the executor down cleanly when the extension is unloaded.
        api.extension().registerUnloadingHandler(() -> {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        });
    }

    private Component buildLoggerTab(MyTableModel table) {
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        UserInterface userInterface = api.userInterface();
        WebSocketMessageEditor messageViewer = userInterface.createWebSocketMessageEditor(READ_ONLY);

        JTabbedPane requestTab = new JTabbedPane();
        requestTab.addTab("Message", messageViewer.uiComponent());
        splitPane.setRightComponent(requestTab);

        JTable jTable = new JTable(table) {
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                super.changeSelection(rowIndex, columnIndex, toggle, extend);
                Object message = table.get(convertRowIndexToModel(rowIndex));
                if (message instanceof InterceptedBinaryMessage) {
                    messageViewer.setContents(((InterceptedBinaryMessage) message).payload());
                } else if (message instanceof InterceptedTextMessage) {
                    messageViewer.setContents(byteArray(((InterceptedTextMessage) message).payload()));
                }
            }
        };

        jTable.setRowHeight(30);

        TableRowSorter<TableModel> sorter = new TableRowSorter<>(table);
        // Sort the '#' column numerically, not lexicographically.
        sorter.setComparator(0, Comparator.comparingInt(o -> (Integer) o));
        jTable.setRowSorter(sorter);
        jTable.getRowSorter().toggleSortOrder(0);

        // Centre-align the '#' column.
        DefaultTableCellRenderer centreRenderer = new DefaultTableCellRenderer();
        centreRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        jTable.getColumnModel().getColumn(0).setCellRenderer(centreRenderer);

        TableColumn idCol = jTable.getColumnModel().getColumn(0);
        idCol.setMinWidth(50);
        idCol.setMaxWidth(100);

        TableColumn hostCol = jTable.getColumnModel().getColumn(1);
        hostCol.setMinWidth(300);
        hostCol.setMaxWidth(700);

        splitPane.setLeftComponent(new JScrollPane(jTable));
        splitPane.setDividerLocation(300);

        return splitPane;
    }
}