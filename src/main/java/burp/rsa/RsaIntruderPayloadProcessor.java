package burp.rsa;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;

public class RsaIntruderPayloadProcessor implements PayloadProcessor {
    private BurpExtender parent;
    private final String extName;
    private final RsaUtil RsaUtil;

    public RsaIntruderPayloadProcessor(final BurpExtender newParent, String extName, RsaConfig config) {
        this.parent = newParent;
        this.extName = extName;
        RsaUtil = new RsaUtil();
        RsaUtil.setConfig(config);
    }

    @Override
    public String displayName() {
        return "BurpCrypto - RSA Encrypt - " + extName;
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData data) {
        try {
            byte[] result = RsaUtil.encrypt(data.currentPayload().getBytes()).getBytes("UTF-8");
            parent.dict.Log(result, data.originalPayload().getBytes());
            return PayloadProcessingResult.usePayload(ByteArray.byteArray(result));
        } catch (Exception e) {
            return PayloadProcessingResult.skipPayload();
        }
    }
}
