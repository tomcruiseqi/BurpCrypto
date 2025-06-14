package burp.des;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;
import java.nio.charset.StandardCharsets;

public class DesIntruderPayloadProcessor implements PayloadProcessor {
    private BurpExtender parent;
    private final String extName;
    private final DesUtil DesUtil;

    public DesIntruderPayloadProcessor(final BurpExtender newParent, String extName, DesConfig config) {
        this.parent = newParent;
        this.extName = extName;
        DesUtil = new DesUtil();
        DesUtil.setConfig(config);
    }

    @Override
    public String displayName() {
        return "BurpCrypto - DES Encrypt - " + extName;
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData data) {
        try {
            byte[] result = DesUtil.encrypt(data.currentPayload().getBytes()).getBytes(StandardCharsets.UTF_8);
            parent.dict.Log(result, data.originalPayload().getBytes());
            return PayloadProcessingResult.usePayload(ByteArray.byteArray(result));
        } catch (Exception e) {
            return PayloadProcessingResult.skipPayload();
        }
    }
}
