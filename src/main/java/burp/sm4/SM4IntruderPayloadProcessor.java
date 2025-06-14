package burp.sm4;

import burp.api.montoya.intruder.PayloadProcessor;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;

public class SM4IntruderPayloadProcessor implements PayloadProcessor {
    private final String extName;
    private final SM4Util SM4Util;

    public SM4IntruderPayloadProcessor(String extName, SM4Config config) {
        this.extName = extName;
        SM4Util = new SM4Util();
        SM4Util.setConfig(config);
    }

    @Override
    public String displayName() {
        return "BurpCrypto - SM4 Encrypt - " + extName;
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData payloadData) {
        try {
            byte[] result = SM4Util.encrypt(payloadData.currentPayload().getBytes()).getBytes("UTF-8");
            return PayloadProcessingResult.usePayload(burp.api.montoya.core.ByteArray.byteArray(result));
        } catch (Exception e) {
            return PayloadProcessingResult.skipPayload();
        }
    }
}
