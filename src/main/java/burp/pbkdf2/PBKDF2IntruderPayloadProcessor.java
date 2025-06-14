package burp.pbkdf2;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;
import burp.utils.OutFormat;
import burp.utils.Utils;
import cn.hutool.crypto.digest.SM3;
import cn.hutool.crypto.symmetric.PBKDF2;

public class PBKDF2IntruderPayloadProcessor implements PayloadProcessor {
    private BurpExtender parent;
    private final String extName;
    private final PBKDF2 pbkdf2;
    private final PBKDF2Config config;

    public PBKDF2IntruderPayloadProcessor(final BurpExtender newParent, String extName, PBKDF2Config config) {
        this.parent = newParent;
        this.extName = extName;
        this.config = (config);
        this.pbkdf2 = new PBKDF2(config.Algorithms.name(), config.KeyLength, config.IterationCount);
    }

    @Override
    public String displayName() {
        return "BurpCrypto - PBKDF2 Encrypt - " + extName;
    }

    private String pbkdf2(byte[] data) {
        byte[] hash = pbkdf2.encrypt(new String(data).toCharArray(), config.Salt);
        return Utils.encode(hash, config.OutFormat);
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData data) {
        try {
            byte[] result = pbkdf2(data.currentPayload().getBytes()).getBytes("UTF-8");
            parent.dict.Log(result, data.originalPayload().getBytes());
            return PayloadProcessingResult.usePayload(ByteArray.byteArray(result));
        } catch (Exception e) {
            return PayloadProcessingResult.skipPayload();
        }
    }
}
