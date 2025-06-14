package burp.sm3;

import burp.utils.OutFormat;
import burp.utils.Utils;
import burp.api.montoya.intruder.PayloadProcessor;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import cn.hutool.crypto.digest.SM3;

public class SM3IntruderPayloadProcessor implements PayloadProcessor {
    private final String extName;
    private final SM3 sm3Utils;
    private final SM3Config config;

    public SM3IntruderPayloadProcessor(String extName, SM3Config config) {
        this.extName = extName;
        this.config = config;
        if (config.Salt != null)
            this.sm3Utils = new SM3(config.Salt);
        else this.sm3Utils = new SM3();
    }

    @Override
    public String displayName() {
        return "BurpCrypto - SM3 Encrypt - " + extName;
    }

    private String SM3Digest(byte[] data) {
        byte[] hash = sm3Utils.digest(data);
        return Utils.encode(hash, config.OutFormat);
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData payloadData) {
        try {
            byte[] result = SM3Digest(payloadData.currentPayload().getBytes()).getBytes("UTF-8");
            return PayloadProcessingResult.usePayload(burp.api.montoya.core.ByteArray.byteArray(result));
        } catch (Exception e) {
            return PayloadProcessingResult.skipPayload();
        }
    }
}
