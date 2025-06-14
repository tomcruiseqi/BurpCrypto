package burp.utils;

import burp.BurpExtender;
import burp.utils.SelectionInfo;
import burp.utils.SelectionLocation;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class BurpCryptoMenuFactory implements ContextMenuItemsProvider {

    private BurpExtender parent;

    public BurpCryptoMenuFactory(BurpExtender parent) {
        this.parent = parent;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        ArrayList<Component> menus = new ArrayList<>();
        JMenuItem menu1 = new JMenuItem("Get PlainText");
        menu1.addActionListener(e -> {
            List<HttpRequestResponse> resps = event.selectedRequestResponses();
            if (resps != null && !resps.isEmpty()) {
                HttpRequestResponse req = resps.get(0);
                ByteArray request = req.request().toByteArray();
                int[] selectedIndexRange = getSelectionBounds(event);
                String selectedText = getSelectedText(request, selectedIndexRange);
                if (selectedText != null && !selectedText.isEmpty()) {
                    String plainText = searchKey(selectedText);
                    if (plainText != null && !plainText.isEmpty()) {
                        ShowCopiableMessage(plainText, "This message plaintext is: ");
                    } else {
                        JOptionPane.showMessageDialog(menu1, "Not found!");
                    }
                }
            }
        });
        menus.add(menu1);
        JMenu quickCrypto = new JMenu("Quick Crypto");
        for (Object obj : parent.IPProcessors.values()) {
            try {
                Object entry = obj;
                JMenuItem _menu = new JMenuItem(entry.getClass().getMethod("getProcessorName").invoke(entry).toString());
                _menu.addActionListener(e -> {
                    try {
                        HttpRequestResponse req = event.selectedRequestResponses().get(0);
                        SelectionInfo sInfo = getSelectionInfo(event);
                        ByteArray data;
                        if (sInfo.Location == null || sInfo.Location.name().equals("Request")) {
                            data = req.request().toByteArray();
                        } else {
                            data = req.response().toByteArray();
                        }
                        int[] selectedIndexRange = getSelectionBounds(event);
                        byte[] selectedBytes = getSelectedBytes(data, selectedIndexRange);
                        if (selectedBytes != null && selectedBytes.length > 0) {
                            byte[] encryptResult = (byte[]) entry.getClass().getMethod("processPayload", byte[].class, byte[].class, byte[].class)
                                .invoke(entry, selectedBytes, selectedBytes, selectedBytes);
                            if (encryptResult != null) {
                                ShowCopiableMessage(new String(encryptResult), "CipherText result: ");
                            } else {
                                JOptionPane.showMessageDialog(_menu, "has error!");
                            }
                        }
                    } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ex) {
                        JOptionPane.showMessageDialog(_menu, "Reflection error: " + ex.getMessage());
                    }
                });
                quickCrypto.add(_menu);
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ex) {
                // 跳过异常的 entry
            }
        }
        if (quickCrypto.getItemCount() > 0) {
            menus.add(quickCrypto);
        }
        return menus;
    }

    private int[] getSelectionBounds(ContextMenuEvent event) {
        // Montoya API: selectionBounds() -> Optional<IntRange>，此处反射兼容，忽略类型警告
        try {
            @SuppressWarnings("unchecked")
            Optional<int[]> boundsOpt = (Optional<int[]>) event.getClass().getMethod("selectionBounds").invoke(event);
            return boundsOpt.orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    private SelectionInfo getSelectionInfo(ContextMenuEvent event) {
        SelectionInfo info = new SelectionInfo();
        switch (event.invocationType()) {
            case MESSAGE_EDITOR_RESPONSE:
            case MESSAGE_VIEWER_RESPONSE:
                info.Location = SelectionLocation.Response;
                break;
            default:
                info.Location = SelectionLocation.Request;
                break;
        }
        switch (event.invocationType()) {
            case MESSAGE_EDITOR_REQUEST:
            case MESSAGE_EDITOR_RESPONSE:
            case INTRUDER_PAYLOAD_POSITIONS:
                info.ReadOnly = false;
                break;
            default:
                info.ReadOnly = true;
        }
        return info;
    }

    public void ShowCopiableMessage(String message, String title) {
        EventQueue.invokeLater(() -> {
            JTextArea ta = new JTextArea(5, 20);
            ta.setText(message);
            ta.setWrapStyleWord(true);
            ta.setLineWrap(true);
            ta.setCaretPosition(0);
            ta.setEditable(false);
            JOptionPane.showMessageDialog(null, new JScrollPane(ta), title, JOptionPane.INFORMATION_MESSAGE);
        });
    }

    private String searchKey(String key) {
        String value = parent.dict.Search(key);
        if (value == null) {
            value = parent.dict.Search(parent.api.utilities().urlUtils().decode(key));
        }
        return value;
    }

    private String getSelectedText(ByteArray request, int[] selectedIndexRange) {
        try {
            return new String(getSelectedBytes(request, selectedIndexRange));
        } catch (Exception ex) {
            return null;
        }
    }

    private byte[] getSelectedBytes(ByteArray request, int[] selectedIndexRange) {
        try {
            if (selectedIndexRange == null) return null;
            byte[] raw = request.getBytes();
            byte[] selectedText = new byte[selectedIndexRange[1] - selectedIndexRange[0]];
            System.arraycopy(raw, selectedIndexRange[0], selectedText, 0, selectedText.length);
            return selectedText;
        } catch (Exception ex) {
            return null;
        }
    }

    public static byte[] Replace(byte[] request, int[] selectedIndexRange, byte[] targetBytes) {
        byte[] result = new byte[request.length - (selectedIndexRange[1] - selectedIndexRange[0]) + targetBytes.length];
        System.arraycopy(request, 0, result, 0, selectedIndexRange[0]);
        System.arraycopy(targetBytes, 0, result, selectedIndexRange[0], targetBytes.length);
        System.arraycopy(request, selectedIndexRange[1], result, selectedIndexRange[0] + targetBytes.length, request.length - selectedIndexRange[1]);
        return result;
    }
}
