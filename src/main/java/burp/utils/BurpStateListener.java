package burp.utils;

import burp.BurpExtender;

import java.io.IOException;

public class BurpStateListener {
    private BurpExtender parent;
    public BurpStateListener(final BurpExtender newParent) {
        this.parent = newParent;
    }
    public void extensionUnloaded() {
        try {
            this.parent.store.close();  // leveldb unload.
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
