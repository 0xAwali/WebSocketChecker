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
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

public class WebSocketChecker implements BurpExtension {

    private MontoyaApi api;
    private ExecutorService scanExecutor;

    @Override
    public void initialize(MontoyaApi montoyaApi) {

        this.api = montoyaApi;
        this.scanExecutor = Executors.newFixedThreadPool(Math.max(4, Runtime.getRuntime().availableProcessors()));

        MyTableModel table = new MyTableModel(api);
        api.extension().setName("WebSocket Sensitive Data Scanner");
        api.userInterface().registerSuiteTab("WebSocket Sensitive Data Scanner", loggerTab(table));
        api.proxy().registerWebSocketCreationHandler(new WebsocketCreatedHandler(table, api, scanExecutor));

        api.extension().registerUnloadingHandler(() -> {
            scanExecutor.shutdown();
            try {
                if (!scanExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    scanExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                scanExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        });
    }

    private Component loggerTab(MyTableModel table) {

        JPanel mainPanel = new JPanel(new BorderLayout());

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

        TableColumn idColumn = jTable.getColumnModel().getColumn(0);
        idColumn.setMinWidth(50);
        idColumn.setMaxWidth(100);

        TableColumn hostColumn = jTable.getColumnModel().getColumn(1);
        hostColumn.setMinWidth(300);
        hostColumn.setMaxWidth(500);

        TableColumn directionColumn = jTable.getColumnModel().getColumn(3);
        directionColumn.setMinWidth(120);
        directionColumn.setMaxWidth(160);

        JScrollPane scrollPane = new JScrollPane(jTable);
        splitPane.setLeftComponent(scrollPane);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> table.clear());

        JButton exportButton = new JButton("Export HTML");
        exportButton.addActionListener(e -> exportToHtml(table, mainPanel));

        toolbar.add(clearButton);
        toolbar.add(exportButton);

        mainPanel.add(toolbar, BorderLayout.NORTH);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        return mainPanel;
    }

    private void exportToHtml(MyTableModel table, Component parent) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("websocket-findings.html"));
        int result = fileChooser.showSaveDialog(parent);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        // rows[0] is the header row ("#", "Host", "Path", "Direction", "Information", "Payload")
        List<String[]> rows = table.exportRows();
        String html = buildHtmlReport(rows);

        try (FileWriter writer = new FileWriter(fileChooser.getSelectedFile())) {
            writer.write(html);
            JOptionPane.showMessageDialog(parent, "Export complete.", "WebSocket Sensitive Data Scanner", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            api.logging().logToError("Failed to export findings: " + e.getMessage());
            JOptionPane.showMessageDialog(parent, "Export failed: " + e.getMessage(), "WebSocket Sensitive Data Scanner", JOptionPane.ERROR_MESSAGE);
        }
    }

    private String buildHtmlReport(List<String[]> rows) {
        List<String[]> dataRows = rows.size() > 1 ? rows.subList(1, rows.size()) : List.of();
        String generatedAt = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .format(java.time.LocalDateTime.now());

        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n");
        sb.append("<title>WebSocket Sensitive Data Scanner - Report</title>\n");
        sb.append("<style>\n").append(reportCss()).append("\n</style>\n</head>\n<body>\n");

        sb.append("<div class=\"header\">\n");
        sb.append("  <h1>WebSocket Sensitive Data Scanner</h1>\n");
        sb.append("  <div class=\"meta\">Generated ").append(escapeHtml(generatedAt))
                .append(" &middot; ").append(dataRows.size()).append(" finding")
                .append(dataRows.size() == 1 ? "" : "s").append("</div>\n");
        sb.append("</div>\n");

        if (dataRows.isEmpty()) {
            sb.append("<div class=\"empty\">No findings to report.</div>\n");
        } else {
            sb.append("<div class=\"findings\">\n");
            for (String[] row : dataRows) {
                String id = row[0];
                String host = row[1];
                String path = row[2];
                String direction = row[3];
                String information = row[4];
                String payload = row[5];

                String directionClass = direction.contains("Client") ? "dir-c2s" : "dir-s2c";

                sb.append("  <div class=\"card\">\n");
                sb.append("    <div class=\"card-header\">\n");
                sb.append("      <span class=\"badge id-badge\">#").append(escapeHtml(id)).append("</span>\n");
                sb.append("      <span class=\"host\">").append(escapeHtml(host)).append("</span>\n");
                sb.append("      <span class=\"path\">").append(escapeHtml(path)).append("</span>\n");
                sb.append("      <span class=\"badge ").append(directionClass).append("\">")
                        .append(escapeHtml(direction)).append("</span>\n");
                sb.append("    </div>\n");

                if (information != null && !information.isEmpty()) {
                    sb.append("    <div class=\"tags\">\n");
                    for (String tag : information.split("\\s*,\\s*")) {
                        if (!tag.isBlank()) {
                            sb.append("      <span class=\"tag\">").append(escapeHtml(tag.trim())).append("</span>\n");
                        }
                    }
                    sb.append("    </div>\n");
                }

                sb.append("    <pre class=\"payload\">").append(escapeHtml(payload)).append("</pre>\n");
                sb.append("  </div>\n");
            }
            sb.append("</div>\n");
        }

        sb.append("</body>\n</html>\n");
        return sb.toString();
    }

    private String reportCss() {
        return """
                :root {
                    color-scheme: light;
                    --bg: #0f172a;
                    --panel: #ffffff;
                    --accent: #6366f1;
                    --text: #1e293b;
                    --muted: #64748b;
                    --border: #e2e8f0;
                    --c2s: #059669;
                    --s2c: #d97706;
                }
                * { box-sizing: border-box; }
                body {
                    margin: 0;
                    padding: 32px;
                    background: linear-gradient(180deg, #0f172a 0%, #1e293b 220px, #f1f5f9 220px);
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    color: var(--text);
                }
                .header { max-width: 1000px; margin: 0 auto 28px; color: #f8fafc; }
                .header h1 { margin: 0 0 6px; font-size: 26px; font-weight: 700; letter-spacing: -0.02em; }
                .header .meta { color: #cbd5e1; font-size: 13px; }
                .findings { max-width: 1000px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
                .empty {
                    max-width: 1000px; margin: 0 auto; background: var(--panel); border: 1px solid var(--border);
                    border-radius: 12px; padding: 32px; text-align: center; color: var(--muted);
                }
                .card {
                    background: var(--panel);
                    border: 1px solid var(--border);
                    border-radius: 12px;
                    padding: 18px 20px;
                    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.06);
                }
                .card-header {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    flex-wrap: wrap;
                    margin-bottom: 10px;
                }
                .host { font-weight: 600; font-size: 14px; }
                .path { color: var(--muted); font-size: 13px; font-family: "SFMono-Regular", Consolas, monospace; }
                .badge {
                    display: inline-block;
                    font-size: 11px;
                    font-weight: 600;
                    padding: 3px 9px;
                    border-radius: 999px;
                    text-transform: uppercase;
                    letter-spacing: 0.03em;
                }
                .id-badge { background: #eef2ff; color: var(--accent); }
                .dir-c2s { background: #ecfdf5; color: var(--c2s); }
                .dir-s2c { background: #fffbeb; color: var(--s2c); }
                .tags { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
                .tag {
                    background: #fef2f2;
                    color: #b91c1c;
                    border: 1px solid #fecaca;
                    font-size: 12px;
                    font-weight: 600;
                    padding: 3px 10px;
                    border-radius: 6px;
                }
                .payload {
                    margin: 0;
                    background: #0f172a;
                    color: #e2e8f0;
                    border-radius: 8px;
                    padding: 14px;
                    font-size: 12.5px;
                    line-height: 1.5;
                    font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
                    max-height: 320px;
                    overflow: auto;
                    white-space: pre-wrap;
                    word-break: break-word;
                }
                """;
    }

    private String escapeHtml(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}