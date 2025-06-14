package burp;

import burp.aes.AesUIHandler;
import burp.des.DesUIHandler;
import burp.execjs.JsUIHandler;
import burp.pbkdf2.PBKDF2UIHandler;
import burp.rsa.RsaUIHandler;
import burp.sm3.SM3UIHandler;
import burp.sm4.SM4UIHandler;
import burp.utils.BurpCryptoMenuFactory;
import burp.utils.DictLogManager;
import burp.utils.Utils;
import burp.zuc.ZUCUIHandler;
import cn.hutool.crypto.SecureUtil;
import org.iq80.leveldb.DB;
import org.iq80.leveldb.Options;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.core.Registration;
import burp.api.montoya.intruder.PayloadProcessor;

import static org.iq80.leveldb.impl.Iq80DBFactory.factory;

public class BurpExtender implements BurpExtension {
    public MontoyaApi api;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public DB store;
    public DictLogManager dict;
    public String version = "0.1.9.1";
    public HashMap<String, PayloadProcessor> IPProcessors = new HashMap<>();
    public JTabbedPane mainPanel;
    public JPanel aesPanel;
    public AesUIHandler AesUI;
    public JPanel rsaPanel;
    public RsaUIHandler RsaUI;
    public JPanel desPanel;
    public DesUIHandler DesUI;
    public JPanel execJsPanel;
    public JsUIHandler JsUI;
    public JPanel sm3Panel;
    public SM3UIHandler SM3UI;
    public JPanel sm4Panel;
    public SM4UIHandler SM4UI;
    public JPanel zucPanel;
    public ZUCUIHandler ZUCUI;
    public JPanel pbkdf2Panel;
    public PBKDF2UIHandler PBKDF2UI;

    // Montoya BurpExtension API required method
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        SecureUtil.disableBouncyCastle();
        Utils.stdout = this.stdout = new PrintWriter(System.out, true);
        Utils.stderr = this.stderr = new PrintWriter(System.err, true);
        api.extension().setName("BurpCrypto v" + version);
        api.userInterface().registerContextMenuItemsProvider(new BurpCryptoMenuFactory(this));
        Options options = new Options();
        options.createIfMissing(true);
        try {
            this.store = factory.open(new File("BurpCrypto.ldb"), options);
            this.dict = new DictLogManager(this);
            api.logging().logToOutput("LevelDb init success!");
        } catch (IOException e) {
            api.logging().logToError("LevelDb init failed! error message: " + e.getMessage());
        }
        stdout.println("BurpCrypto loaded successfully!\r\n");
        stdout.println("Anthor: Whwlsfb");
        stdout.println("Email: whwlsfb@wanghw.cn");
        stdout.println("Github: https://github.com/whwlsfb/BurpCrypto");
        InitUi();
    }

    private void InitUi() {
        this.AesUI = new AesUIHandler(this);
        this.RsaUI = new RsaUIHandler(this);
        this.JsUI = new JsUIHandler(this);
        this.DesUI = new DesUIHandler(this);
        this.SM3UI = new SM3UIHandler(this);
        this.SM4UI = new SM4UIHandler(this);
        this.ZUCUI = new ZUCUIHandler(this);
        this.PBKDF2UI = new PBKDF2UIHandler(this);
        SwingUtilities.invokeLater(() -> {
            BurpExtender bthis = BurpExtender.this;
            bthis.mainPanel = new JTabbedPane();
            bthis.aesPanel = AesUI.getPanel();
            bthis.mainPanel.addTab("AES", bthis.aesPanel);
            bthis.rsaPanel = RsaUI.getPanel();
            bthis.mainPanel.addTab("RSA", bthis.rsaPanel);
            bthis.desPanel = DesUI.getPanel();
            bthis.mainPanel.addTab("DES", bthis.desPanel);
            bthis.sm3Panel = SM3UI.getPanel();
            bthis.mainPanel.addTab("SM3", bthis.sm3Panel);
            bthis.sm4Panel = SM4UI.getPanel();
            bthis.mainPanel.addTab("SM4", bthis.sm4Panel);
            bthis.zucPanel = ZUCUI.getPanel();
            bthis.mainPanel.addTab("ZUC", bthis.zucPanel);
            bthis.pbkdf2Panel = PBKDF2UI.getPanel();
            bthis.mainPanel.addTab("PBKDF2", bthis.pbkdf2Panel);
            bthis.execJsPanel = JsUI.getPanel();
            bthis.mainPanel.addTab("Exec Js", bthis.execJsPanel);
            api.userInterface().registerSuiteTab("BurpCrypto", bthis.mainPanel);
        });
    }

    /**
     * 注册 Intruder PayloadProcessor
     */
    public void regIPProcessor(String name, PayloadProcessor processor) {
        if (!IPProcessors.containsKey(name)) {
            IPProcessors.put(name, processor);
            api.intruder().registerPayloadProcessor(processor);
            if (stdout != null) stdout.println("[BurpCrypto] 注册PayloadProcessor: " + name);
        }
    }

    /**
     * 移除 Intruder PayloadProcessor（仅移除本地引用，Burp API 无法主动注销）
     */
    public void removeIPProcessor(String name) {
        if (IPProcessors.containsKey(name)) {
            IPProcessors.remove(name);
            if (stdout != null) stdout.println("[BurpCrypto] 移除PayloadProcessor: " + name);
        }
    }

    public void extensionUnloaded() {
        try {
            if (this.store != null) this.store.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (stdout != null) stdout.println("[BurpCrypto] Extension unloaded, LevelDB closed.");
    }
}
