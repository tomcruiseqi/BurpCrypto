package burp.zuc;

import burp.api.montoya.intruder.PayloadProcessor;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;

public class ZUCIntruderPayloadProcessor implements PayloadProcessor {
    private final String extName;
    private final ZUCUtil ZUCUtil;

    public ZUCIntruderPayloadProcessor(String extName, ZUCConfig config) {
        this.extName = extName;
        ZUCUtil = new ZUCUtil();
        ZUCUtil.setConfig(config);
    }

    @Override
    public String displayName() {
        return "BurpCrypto - ZUC Encrypt - " + extName;
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData payloadData) {
        try {
            byte[] result = ZUCUtil.encrypt(payloadData.currentPayload().getBytes()).getBytes("UTF-8");
            return PayloadProcessingResult.usePayload(burp.api.montoya.core.ByteArray.byteArray(result));
        } catch (Exception e) {
            return PayloadProcessingResult.skipPayload();
        }
    }
}
