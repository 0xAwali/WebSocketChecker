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

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

public class WebSocketChecker implements BurpExtension {


    MontoyaApi api;

    @Override
    public void initialize(MontoyaApi montoyaApi) {

        this.api = montoyaApi;
        MyTableModel table = new MyTableModel(api);
        api.extension().setName("WebSocket Checker");
        api.userInterface().registerSuiteTab("Websocket Checker", LoggerTab(table));
        api.proxy().registerWebSocketCreationHandler(new WebsocketCreatedHandler(table,api));

    }

    private Component LoggerTab(MyTableModel table) {

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);


        UserInterface userInterface = api.userInterface();
        WebSocketMessageEditor textMessageViewer = userInterface.createWebSocketMessageEditor(READ_ONLY);
        JTabbedPane requestTab = new JTabbedPane();
        requestTab.addTab("Message", textMessageViewer.uiComponent());


        splitPane.setRightComponent(requestTab);

        JTable jTable = new JTable(table) {
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                super.changeSelection(rowIndex, columnIndex, toggle, extend);
                Object message = table.get(convertRowIndexToModel(rowIndex));
                if (message instanceof InterceptedBinaryMessage) {
                    InterceptedBinaryMessage binaryMessage = (InterceptedBinaryMessage) message;
                    textMessageViewer.setContents(binaryMessage.payload());
                } else if (message instanceof InterceptedTextMessage) {
                    InterceptedTextMessage textMessage = (InterceptedTextMessage) message;
                    textMessageViewer.setContents(byteArray(textMessage.payload()));
                }
            }
        };

        jTable.setRowHeight(30);
        jTable.setAutoCreateRowSorter(true);
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(table);
        jTable.setRowSorter(sorter);

        sorter.setComparator(0, new Comparator<Integer>() {
            @Override
            public int compare(Integer o1, Integer o2) {
                return o1.compareTo(o2); // Compare as integers
            }
        });

        jTable.getRowSorter().toggleSortOrder(0);

        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        jTable.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);

        TableColumn ID = jTable.getColumnModel().getColumn(0);
        ID.setMinWidth(50);
        ID.setMaxWidth(100);

        TableColumn Host = jTable.getColumnModel().getColumn(1);
        Host.setMinWidth(600);
        Host.setMaxWidth(700);


        JScrollPane scrollPane = new JScrollPane(jTable);
        splitPane.setLeftComponent(scrollPane);

        return splitPane;
    }
}
