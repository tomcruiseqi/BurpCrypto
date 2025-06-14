package burp.montoya;

import burp.api.montoya.intruder.PayloadProcessor;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;

/**
 * Montoya API 2025.6 兼容的 IntruderPayloadProcessor 抽象基类
 */
public abstract class MontoyaIntruderPayloadProcessor implements PayloadProcessor {
    @Override
    public String displayName() {
        return name();
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData data) {
        // Montoya API 2025.6 的 PayloadData 没有 baseValue 字段
        byte[] result = process(data.currentPayload().getBytes(), data.originalPayload().getBytes(), null);
        if (result == null) {
            return PayloadProcessingResult.skipPayload();
        }
        return PayloadProcessingResult.usePayload(burp.api.montoya.core.ByteArray.byteArray(result));
    }

    public abstract String name();
    public abstract byte[] process(byte[] currentPayload, byte[] originalPayload, byte[] baseValue);
}
