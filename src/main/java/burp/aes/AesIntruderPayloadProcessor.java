package burp.aes;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;

public class AesIntruderPayloadProcessor implements PayloadProcessor {
    private BurpExtender parent;
    private final String extName;
    private final AesUtil AesUtil;

    public AesIntruderPayloadProcessor(final BurpExtender newParent, String extName, AesConfig config) {
        this.parent = newParent;
        this.extName = extName;
        AesUtil = new AesUtil();
        AesUtil.setConfig(config);
    }

    @Override
    public String displayName() {
        return "BurpCrypto - AES Encrypt - " + extName;
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData data) {
        try {
            byte[] result = AesUtil.encrypt(data.currentPayload().getBytes()).getBytes("UTF-8");
            parent.dict.Log(result, data.originalPayload().getBytes());
            return PayloadProcessingResult.usePayload(ByteArray.byteArray(result));
        } catch (Exception e) {
            // 可选：parent.api.logging().logToError(e.toString());
            return PayloadProcessingResult.skipPayload();
        }
    }
}
