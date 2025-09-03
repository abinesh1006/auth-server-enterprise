package com.example.authserver.mfa;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;

public class TotpService {
    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;

    public static String generateSecret() {
        byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        return new Base32().encodeToString(bytes);
    }

    public static boolean verifyCode(String base32Secret, String code) {
        long t = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
        for (long i=-1; i<=1; i++) if (generateCode(base32Secret, t+i).equals(code)) return true;
        return false;
    }

    public static String generateCode(String base32Secret, long timeIndex) {
        try {
            Base32 base32 = new Base32();
            byte[] key = base32.decode(base32Secret);
            ByteBuffer buffer = ByteBuffer.allocate(8).putLong(timeIndex);
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(buffer.array());
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7f) << 24) |
                         ((hash[offset+1] & 0xff) << 16) |
                         ((hash[offset+2] & 0xff) << 8) |
                         (hash[offset+3] & 0xff);
            int otp = binary % 1000000;
            return String.format("%06d", otp);
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
}
