package burp.execjs;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;
import burp.execjs.engine.HtmlUnitEngine;
import burp.execjs.engine.JreBuiltInEngine;
import burp.execjs.engine.RhinoEngine;

import java.nio.charset.StandardCharsets;

public class ExecJSIntruderPayloadProcessor implements PayloadProcessor {
    private BurpExtender parent;
    private final String extName;
    private final IJsEngine jsEngine;

    public ExecJSIntruderPayloadProcessor(final BurpExtender newParent, String extName, JsConfig config) {
        this.parent = newParent;
        this.extName = extName;
        switch (config.JsEngine){
            case HtmlUnit:
                this.jsEngine = new HtmlUnitEngine();
                break;
            case JreBuiltIn:
                this.jsEngine = new JreBuiltInEngine();
                break;
            default:
                this.jsEngine = new RhinoEngine();
        }
        this.jsEngine.setParent(parent);
        try {
            this.jsEngine.setConfig(config);
        } catch (Exception e) {
            // 可选：parent.api.logging().logToError(e.toString());
        }
    }

    @Override
    public String displayName() {
        return "BurpCrypto - Exec JS - " + extName;
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData data) {
        try {
            byte[] result = jsEngine.eval(new String(data.currentPayload().getBytes(), StandardCharsets.UTF_8)).getBytes("UTF-8");
            parent.dict.Log(result, data.originalPayload().getBytes());
            return PayloadProcessingResult.usePayload(ByteArray.byteArray(result));
        } catch (Exception e) {
            return PayloadProcessingResult.skipPayload();
        }
    }
}
