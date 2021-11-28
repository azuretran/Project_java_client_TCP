/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

import com.microsoft.sqlserver.jdbc.SQLServerDataSource;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/**
 *
 * @author azure Tran
 */
public class ServerTcp {

    /**
     * IP thay thế ban đầu
     */
    
    
    
    
    
    /* encrypt file and decrypt file
    
   */
    public static void encrypt(String key, InputStream is, OutputStream os) throws Throwable {
		encryptOrDecrypt(key, Cipher.ENCRYPT_MODE, is, os);
	}

	public static void decrypt(String key, InputStream is, OutputStream os) throws Throwable {
		encryptOrDecrypt(key, Cipher.DECRYPT_MODE, is, os);
	}

	public static void encryptOrDecrypt(String key, int mode, InputStream is, OutputStream os) throws Throwable {

		DESKeySpec dks = new DESKeySpec(key.getBytes());
		SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		SecretKey desKey = skf.generateSecret(dks);
		Cipher cipher = Cipher.getInstance("DES"); // DES/ECB/PKCS5Padding for SunJCE

		if (mode == Cipher.ENCRYPT_MODE) {
			cipher.init(Cipher.ENCRYPT_MODE, desKey);
			CipherInputStream cis = new CipherInputStream(is, cipher);
			doCopy(cis, os);
		} else if (mode == Cipher.DECRYPT_MODE) {
			cipher.init(Cipher.DECRYPT_MODE, desKey);
			CipherOutputStream cos = new CipherOutputStream(os, cipher);
			doCopy(is, cos);
		}
	}

	public static void doCopy(InputStream is, OutputStream os) throws IOException {
		byte[] bytes = new byte[64];
		int numBytes;
		while ((numBytes = is.read(bytes)) != -1) {
			os.write(bytes, 0, numBytes);
		}
		os.flush();
		os.close();
		is.close();
	}
    /*-------------------------------------------------------------------------*/
    private static final byte[] pc_first = {-1, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    };

    /**
     * Đảo ngược ip ban đầu^{-1}
     */
    private static final byte[] pc_last = {-1, 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    };

    /**
     * hép toán hoán vị P
     */
    private static final byte[] des_P = {-1, 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26,
        5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
        9, 13, 30, 6, 22, 11, 4, 25
    };

    /**
     * Chọn hoạt động mở rộng Hộp E
     */
    private static final byte[] des_E = {-1, 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };

    /**
     * Chọn hoạt động nén S-box
     */
    private static final byte[][] des_S = {
        {-1, 0xe, 0x0, 0x4, 0xf, 0xd, 0x7, 0x1, 0x4, 0x2, 0xe, 0xf, 0x2, 0xb,
            0xd, 0x8, 0x1, 0x3, 0xa, 0xa, 0x6, 0x6, 0xc, 0xc, 0xb, 0x5, 0x9,
            0x9, 0x5, 0x0, 0x3, 0x7, 0x8, 0x4, 0xf, 0x1, 0xc, 0xe, 0x8, 0x8,
            0x2, 0xd, 0x4, 0x6, 0x9, 0x2, 0x1, 0xb, 0x7, 0xf, 0x5, 0xc, 0xb,
            0x9, 0x3, 0x7, 0xe, 0x3, 0xa, 0xa, 0x0, 0x5, 0x6, 0x0, 0xd},//Phần này vô dụng, chỉ có chỗ

        {-1, 0xe, 0x0, 0x4, 0xf, 0xd, 0x7, 0x1, 0x4, 0x2, 0xe, 0xf, 0x2, 0xb,
            0xd, 0x8, 0x1, 0x3, 0xa, 0xa, 0x6, 0x6, 0xc, 0xc, 0xb, 0x5, 0x9,
            0x9, 0x5, 0x0, 0x3, 0x7, 0x8, 0x4, 0xf, 0x1, 0xc, 0xe, 0x8, 0x8,
            0x2, 0xd, 0x4, 0x6, 0x9, 0x2, 0x1, 0xb, 0x7, 0xf, 0x5, 0xc, 0xb,
            0x9, 0x3, 0x7, 0xe, 0x3, 0xa, 0xa, 0x0, 0x5, 0x6, 0x0, 0xd},
        {-1, 0xf, 0x3, 0x1, 0xd, 0x8, 0x4, 0xe, 0x7, 0x6, 0xf, 0xb, 0x2, 0x3,
            0x8, 0x4, 0xf, 0x9, 0xc, 0x7, 0x0, 0x2, 0x1, 0xd, 0xa, 0xc, 0x6,
            0x0, 0x9, 0x5, 0xb, 0xa, 0x5, 0x0, 0xd, 0xe, 0x8, 0x7, 0xa, 0xb,
            0x1, 0xa, 0x3, 0x4, 0xf, 0xd, 0x4, 0x1, 0x2, 0x5, 0xb, 0x8, 0x6,
            0xc, 0x7, 0x6, 0xc, 0x9, 0x0, 0x3, 0x5, 0x2, 0xe, 0xf, 0x9},
        {-1, 0xa, 0xd, 0x0, 0x7, 0x9, 0x0, 0xe, 0x9, 0x6, 0x3, 0x3, 0x4, 0xf,
            0x6, 0x5, 0xa, 0x1, 0x2, 0xd, 0x8, 0xc, 0x5, 0x7, 0xe, 0xb, 0xc,
            0x4, 0xb, 0x2, 0xf, 0x8, 0x1, 0xd, 0x1, 0x6, 0xa, 0x4, 0xd, 0x9,
            0x0, 0x8, 0x6, 0xf, 0x9, 0x3, 0x8, 0x0, 0x7, 0xb, 0x4, 0x1, 0xf,
            0x2, 0xe, 0xc, 0x3, 0x5, 0xb, 0xa, 0x5, 0xe, 0x2, 0x7, 0xc},
        {-1, 0x7, 0xd, 0xd, 0x8, 0xe, 0xb, 0x3, 0x5, 0x0, 0x6, 0x6, 0xf, 0x9,
            0x0, 0xa, 0x3, 0x1, 0x4, 0x2, 0x7, 0x8, 0x2, 0x5, 0xc, 0xb, 0x1,
            0xc, 0xa, 0x4, 0xe, 0xf, 0x9, 0xa, 0x3, 0x6, 0xf, 0x9, 0x0, 0x0,
            0x6, 0xc, 0xa, 0xb, 0xa, 0x7, 0xd, 0xd, 0x8, 0xf, 0x9, 0x1, 0x4,
            0x3, 0x5, 0xe, 0xb, 0x5, 0xc, 0x2, 0x7, 0x8, 0x2, 0x4, 0xe},
        {-1, 0x2, 0xe, 0xc, 0xb, 0x4, 0x2, 0x1, 0xc, 0x7, 0x4, 0xa, 0x7, 0xb,
            0xd, 0x6, 0x1, 0x8, 0x5, 0x5, 0x0, 0x3, 0xf, 0xf, 0xa, 0xd, 0x3,
            0x0, 0x9, 0xe, 0x8, 0x9, 0x6, 0x4, 0xb, 0x2, 0x8, 0x1, 0xc, 0xb,
            0x7, 0xa, 0x1, 0xd, 0xe, 0x7, 0x2, 0x8, 0xd, 0xf, 0x6, 0x9, 0xf,
            0xc, 0x0, 0x5, 0x9, 0x6, 0xa, 0x3, 0x4, 0x0, 0x5, 0xe, 0x3},
        {-1, 0xc, 0xa, 0x1, 0xf, 0xa, 0x4, 0xf, 0x2, 0x9, 0x7, 0x2, 0xc, 0x6,
            0x9, 0x8, 0x5, 0x0, 0x6, 0xd, 0x1, 0x3, 0xd, 0x4, 0xe, 0xe, 0x0,
            0x7, 0xb, 0x5, 0x3, 0xb, 0x8, 0x9, 0x4, 0xe, 0x3, 0xf, 0x2, 0x5,
            0xc, 0x2, 0x9, 0x8, 0x5, 0xc, 0xf, 0x3, 0xa, 0x7, 0xb, 0x0, 0xe,
            0x4, 0x1, 0xa, 0x7, 0x1, 0x6, 0xd, 0x0, 0xb, 0x8, 0x6, 0xd},
        {-1, 0x4, 0xd, 0xb, 0x0, 0x2, 0xb, 0xe, 0x7, 0xf, 0x4, 0x0, 0x9, 0x8,
            0x1, 0xd, 0xa, 0x3, 0xe, 0xc, 0x3, 0x9, 0x5, 0x7, 0xc, 0x5, 0x2,
            0xa, 0xf, 0x6, 0x8, 0x1, 0x6, 0x1, 0x6, 0x4, 0xb, 0xb, 0xd, 0xd,
            0x8, 0xc, 0x1, 0x3, 0x4, 0x7, 0xa, 0xe, 0x7, 0xa, 0x9, 0xf, 0x5,
            0x6, 0x0, 0x8, 0xf, 0x0, 0xe, 0x5, 0x2, 0x9, 0x3, 0x2, 0xc},
        {-1, 0xd, 0x1, 0x2, 0xf, 0x8, 0xd, 0x4, 0x8, 0x6, 0xa, 0xf, 0x3, 0xb,
            0x7, 0x1, 0x4, 0xa, 0xc, 0x9, 0x5, 0x3, 0x6, 0xe, 0xb, 0x5, 0x0,
            0x0, 0xe, 0xc, 0x9, 0x7, 0x2, 0x7, 0x2, 0xb, 0x1, 0x4, 0xe, 0x1,
            0x7, 0x9, 0x4, 0xc, 0xa, 0xe, 0x8, 0x2, 0xd, 0x0, 0xf, 0x6, 0xc,
            0xa, 0x9, 0xd, 0x0, 0xf, 0x3, 0x3, 0x5, 0x5, 0x6, 0x8, 0xb}

    };

    /**
     * PC-1
     */
    private static final byte[] keyleftright = {
        -1, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    };

    /**
     * Phím xoay sang trái
     */
    private static final byte[] lefttable = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    /**
     * PC-2
     */
    private static final byte[] keychoose = {
        -1, 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    };

    /**
     * Bản rõ được mã hóa
     */
    private String plaintext;

    /**
     * Bản mã được giải mã
     */
    private String ciphertext;

    /**
     * Khóa ban đầu
     */
    private String srcKey;

    /**
     * Khóa con cho 16 lần lặp
     */
    private String[] keys = new String[16];

    /**
     * Lựa chọn chế độ, true nghĩa là mã hóa, false nghĩa là giải mã
     */
    private boolean mode;

    /**
     * Phương pháp xây dựng
     *
     * @param k khóa ban đầu (giới hạn 8 ký tự)
     * @Throws DESException 8 khi khóa không phải là số ký tự Ném
     */
    public ServerTcp(String k) throws DESException {
        try {
            //Sử dụng thống nhất mã hóa và giải mã utf-8 để tránh các tình huống có thể bị cắt xén
            if (k.getBytes("utf-8").length != 8) {
                throw new DESException("Độ dài của khóa không được lớn hơn 8!");
            }
        } catch (UnsupportedEncodingException e) {
            // TODO khối bắt được tạo tự động
            e.printStackTrace();
        }
        srcKey = k;
        genKey();//Tạo 16 khóa con tại đây
    }

    /**
     * Nhận kết quả mã hóa hoặc giải mã Văn bản nguồn văn bản @param, văn bản
     * nguồn được mã hóa là chuỗi gốc và văn bản nguồn được giải mã là chuỗi nhị
     * phân được mã hóa Lựa chọn chế độ @param m, đúng đối với mã hóa, sai đối
     * với giải mã
     *
     * @ quay lại kết quả mã hóa hoặc giải mã
     */
    public String getResult(String text, boolean m) {
        mode = m;
        if (mode == true) {
            plaintext = text;
            encry();
            return ciphertext;
        } else {
            ciphertext = text;
            decry();
            return plaintext;
        }
    }

    /**
     * Chuỗi nhị phân XOR
     *
     * @param s1 toán hạng 1
     * @param s2 toán hạng 2
     * @return s1 và s2 kết quả XOR
     */
    private static String strxor(String s1, String s2) {
        int len = s1.length() > s2.length() ? s1.length() : s2.length(); //true thì s1, false thì s2
        StringBuilder s = new StringBuilder(); // Tạo ra một Builder chuỗi với dung lượng ban đầu là 16
        for (int i = 0; i < len; i++) {
            if (i >= s1.length() || i >= s2.length()) {
                s.append("0");
            } else {
                if (s1.charAt(i) == s2.charAt(i)) { //trả về giá trị Char của chuỗi tại vị trí có chỉ số index được chỉ định được chỉ định. Index bắt đầu từ 0.
                    s.append("0");
                } else {
                    s.append("1");
                }
            }
        }
        return s.toString();
    }

    /**
     * Chuyển một số int thành dạng chuỗi nhị phân.
     *
     * @param num kiểu dữ liệu int sẽ được chuyển đổi
     * @param digits chữ số nhị phân cần chuyển đổi, nếu số chữ số không đủ, hãy
     * thêm số 0 ở phía trước
     * @return dạng chuỗi nhị phân
     */
    public static String toBinary(int num, int digits) { //degits = 64
        String s = Integer.toBinaryString(num); //chuyển về binary
        if (s.length() < digits) {
            String cover = Integer.toBinaryString(1 << digits).substring(1);
            return cover.substring(s.length()) + s;
        } else if (s.length() > digits) { //nếu số chữ số không đủ, thêm số 0 ở phía trước
            return s.substring(s.length() - digits);
        } else {
            return s;
        }
    }

    /**
     * Tạo chuỗi văn bản nhị phân
     *
     * @param src chuỗi được chuyển đổi Kết quả chuyển đổi @return
     */
    private static String genBinaryMsg(String src) {
        byte[] b = null;
        try {
            b = src.getBytes("utf-8");
        } catch (UnsupportedEncodingException e) {

            e.printStackTrace();
        }
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            s.append(toBinary(b[i], 8));
        }
        return s.toString();
    }

    /**
     * Kiểm tra xem độ dài của chuỗi nhị phân có phải là 64 bit hay không
     *
     * @param src chuỗi được chuyển đổi Chuỗi 64 bit được tạo bởi @return
     */
    private static String check64(String src) {
        if (src.length() == 64) {
            return src;
        }
        if (src.length() > 64)//lớn hơn 64 thì lấy 64 bit đầu tiên
        {
            return src.substring(0, 64);
        }
        StringBuilder s = new StringBuilder();
        s.append(src);
        int len = 64 - src.length();
        for (int i = 0; i < len; i++) {
            s.append("0");//Thêm 0 vào cuối nếu nó nhỏ hơn 64 bit
        }
        return s.toString();
    }

    /**
     * Chuyển một số int thành dạng chuỗi nhị phân và chữ số cuối cùng là mã
     * kiểm tra lẻ
     *
     * @param num kiểu dữ liệu int sẽ được chuyển đổi
     * @return dạng chuỗi nhị phân
     * @Throws khi DESException khi nó không phải là các ký tự chính trong mã
     * ASCII, Ném
     */
    public static String toCheckedBinary(int num) throws DESException {
        String s = Integer.toBinaryString(num);
        if (s.length() > 7) {
            throw new DESException("Khóa phải là Ascii !");
        }
        int count1 = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '1') {
                count1++;
            }
        }
        if (count1 % 2 == 0) {
            return s + "1";
        } else {
            return s + "0";
        }
    }

    /**
     * Tạo chuỗi khóa nhị phân
     *
     * @param src chuỗi được chuyển đổi
     * @param len chỉ định số chữ số Kết quả chuyển đổi @return
     */
    private static String genBinaryKey(String src, int len) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < len; i++) {
            s.append(toCheckedBinary(src.charAt(i)));
        }
        return s.toString();
    }

    /**
     * Chuyển đổi mảng Byte thành mảng byte
     *
     * @param B Byte mảng được chuyển đổi
     * @return mảng byte được chuyển đổi
     */
    private byte[] Byte2byte(Byte[] B) {
        byte[] b = new byte[B.length];
        for (int i = 0; i < b.length; i++) {
            b[i] = B[i];
        }
        return b;
    }

    /**
     * Chuỗi nhị phân thành chuỗi thông thường
     *
     * @param src chuỗi được chuyển đổi Kết quả chuyển đổi @return
     */
    private String binary2String(String src) {
        List<Byte> list = new ArrayList<Byte>();
        for (int i = 0; i < src.length(); i += 8) {
            list.add((byte) (Integer.parseInt(src.substring(i, i + 8), 2))); //sử dụng để chuyển String sang Int trong Java
        }
        byte[] b = Byte2byte(list.toArray(new Byte[list.size()]));
        String s = null;
        try {
            s = new String(b, "utf-8");
        } catch (UnsupportedEncodingException e) {
            // khối bắt được tạo tự động
            e.printStackTrace();
        }
        if (mode == true) {
            return s;
        } else { //Nếu là giải mã, bạn phải xóa phần đuôi để làm tròn 64-bit \ 0. Java đếm \ 0 là độ dài của chuỗi
            return s.replaceAll("\0+$", "");
        }
    }

    /**
     * IP thay thế ban đầu
     *
     * @param src Chuỗi nhị phân tương ứng với văn bản nguồn được chuyển đổi Kết
     * quả chuyển đổi @return , dưới dạng giá trị ban đầu của 16 lần lặp
     */
    private String firstIP(String src) {
        src = "0" + src;
        StringBuilder s = new StringBuilder();
        for (int i = 1; i <= 64; i++) {
            s.append(src.charAt(pc_first[i]));
        }
        return s.toString();
    }

    /**
     * Đảo ngược IP thay thế ban đầu ^ {- 1}
     *
     * @param src Chuỗi nhị phân được chuyển đổi Kết quả chuyển đổi @return ,
     * sau đó được chuyển đổi thành chuỗi thông thường do mã hóa hoặc giải mã
     */
    private String lastIP(String src) {
        src = "0" + src;
        StringBuilder s = new StringBuilder();
        for (int i = 1; i <= 64; i++) {
            s.append(src.charAt(pc_last[i]));
        }
        return s.toString();
    }

    /**
     * Chọn hoạt động mở rộng E
     *
     * @param right Lặp lại nửa bên phải của kết quả trung gian Kết quả chuyển
     * đổi @return và sau đó hoạt động XOR với khóa con
     */
    private String ope_E(String right) {
        String r = "0" + right;
        StringBuilder s = new StringBuilder();
        for (int i = 1; i <= 48; i++) {
            s.append(r.charAt(des_E[i]));
        }
        return s.toString();
    }

    /**
     * Chọn thao tác nén S để nén chuỗi nhị phân 48 bit thành 32 bit
     *
     * @param right Kết quả XOR của nửa bên phải của kết quả trung gian và khóa
     * con
     * @return kết quả chuyển đổi 32-bit, như là đầu vào của hoạt động P
     */
    private String ope_S(String right) {
        String r = "0" + right;
        StringBuilder s = new StringBuilder();
        int j = 1;
        for (int i = 1; i <= 48; i += 6) {
            String temp = r.substring(i, i + 6);
            s.append(toBinary(des_S[j][Integer.parseInt(temp, 2)], 4));
            j++;
        }
        return s.toString();
    }

    /**
     * Phép toán hoán vị P
     *
     * @param right Kết quả của phép toán S Kết quả chuyển đổi @return , là giá
     * trị ban đầu của lần lặp tiếp theo trong 16 lần lặp
     */
    private String ope_P(String right) {
        String r = "0" + right;
        StringBuilder s = new StringBuilder();
        for (int i = 1; i <= 32; i++) {
            s.append(r.charAt(des_P[i]));
        }
        return s.toString();
    }

    /**
     * 16 lần lặp của hàm f, bao gồm hoạt động E, hoạt động XOR với khóa con,
     * hoạt động S, hoạt động P
     *
     * @param right Giá trị ban đầu của nửa bên phải của lần lặp này Khóa @param
     * Khóa con của lần lặp này
     * @return kết quả chuyển đổi, sau đó XOR với nửa bên trái của lần lặp này
     * là nửa bên phải của lần lặp tiếp theo
     */
    private String f(String right, String key) {
        String addResult = strxor(ope_E(right), key);
        return ope_P(ope_S(addResult));
    }

    /**
     * 16 lần lặp
     *
     * @param left Nửa bên trái của IP thay thế ban đầu
     * @param right Nửa bên phải của IP thay thế ban đầu
     * @return Sau 16 lần lặp lại, các phần bên trái và bên phải được trao đổi
     * và sau đó được nối với nhau, làm đầu vào của IP thay thế ban đầu nghịch
     * đảo ^ {- 1}
     */
    private String itra16(String left, String right) {
        if (mode == true) {
            for (int i = 0; i < 16; i++) {
                String copyLeft = left;
                left = right;
                right = strxor(copyLeft, f(right, keys[i]));
            }
        } else {
            for (int i = 15; i >= 0; i--) {
                String copyLeft = left;
                left = right;
                right = strxor(copyLeft, f(right, keys[i]));
            }
        }
        return right + left; //Lưu ý rằng sau 16 lần lặp, bạn cần trao đổi các phần bên trái và bên phải rồi ghép nối
    }

    /**
     * Sử dụng phím 64 bit ban đầu để thay thế để chọn hoạt động PC-1
     *
     * @return 56-bit đầu ra bit hiệu dụng, kết quả [0] là nửa bên trái, kết quả
     * [1] là nửa bên phải, sau khi xuất kết quả, một quá trình dịch chuyển sang
     * trái theo chu kỳ
     */
    private String[] ope_pc_1() {
        String[] result = new String[2];
        String src = "0" + genBinaryKey(srcKey, 8);
        StringBuilder s = new StringBuilder();
        // Tạo chuỗi nhị phân tương ứng với khóa ban đầu: mỗi ký tự của khóa ban đầu là 8 bit và bit thứ 8 là mã kiểm tra lẻ
        // Ngay cả khi số lượng 1 xuất hiện trong mỗi 8 bit là số lẻ
        for (int i = 1; i <= 56; i++) {
            s.append(src.charAt(keyleftright[i]));
        }
        //Tách khóa 56-bit thành các phần bên trái và bên phải
        result[0] = s.toString().substring(0, 28);
        result[1] = s.toString().substring(28);
        return result;
    }

    /**
     * Thao tác sang trái theo chu kỳ phím
     *
     * @param src Chuỗi nhị phân xoay trái
     * @param lập chỉ mục số bit để xoay trái
     * @ quay lại kết quả của sự dịch chuyển bên trái
     */
    private String ope_shift(String src, int index) {
        return src.substring(index) + src.substring(0, index);
    }

    /**
     * Thay thế khóa chọn thao tác PC-2 để tạo khóa phụ 48 bit
     *
     * @param src Kết quả của việc nối hai bộ phận sau khi thao tác sang trái
     * @return khóa con 48-bit
     */
    private String ope_pc_2(String src) {
        src = "0" + src;
        StringBuilder s = new StringBuilder();
        for (int i = 1; i <= 48; i++) {
            s.append(src.charAt(keychoose[i]));
        }
        return s.toString();
    }

    /**
     * Tạo khóa con được sử dụng cho 16 lần lặp
     */
    private void genKey() {
        String[] temp = ope_pc_1();
        for (int i = 0; i < 16; i++) {
            temp[0] = ope_shift(temp[0], lefttable[i]);
            temp[1] = ope_shift(temp[1], lefttable[i]);
            keys[i] = ope_pc_2(temp[0] + temp[1]);//Các bộ phận bên trái và bên phải được nối và việc thay thế phím được thực hiện để chọn hoạt động PC-2
        }
    }

    /**
     * Mã hóa tạo ra một chuỗi nhị phân, được mã hóa sau mỗi 8 byte
     */
    private void encry() {
        String temp = "";
        String binary = genBinaryMsg(plaintext);//Chuyển đổi bản rõ thành chuỗi nhị phân, sử dụng mã hóa utf-8
        for (int i = 0; i < binary.length(); i += 64) {
            String s = firstIP(check64(binary.substring(i)));
            temp += lastIP(itra16(s.substring(0, 32), s.substring(32)));//kết quả của hoán vị ban đầu chỉ IP là chia thành nhiều phần trái và phải
        }
        ciphertext = temp;//Kết quả mã hóa được xuất dưới dạng chuỗi nhị phân
    }

    /**
     * Giải mã chuỗi nhị phân để tạo bản rõ, giải mã sau mỗi 8 byte
     */
    private void decry() {
        String temp = "";
        String binary = ciphertext;
        //Đầu tiên hãy kiểm tra xem bản mã đầu vào có phải là một chuỗi nhị phân hay không
        for (int i = 0; i < binary.length(); i++) {
            if (binary.charAt(i) != '0' && binary.charAt(i) != '1') {
                throw new DESException("The ciphertext must be binary string !");
            }
        }
        for (int i = 0; i < binary.length(); i += 64) {
            String s = firstIP(check64(binary.substring(i)));
            temp += lastIP(itra16(s.substring(0, 32), s.substring(32)));// kết quả của hoán vị ban đầu chỉ IP là chia thành nhiều phần trái và phải
        }
        plaintext = binary2String(temp); //Chuyển đổi chuỗi nhị phân được tạo bằng giải mã thành chuỗi bình thường và chuyển đổi nó theo mã hóa utf-8
    }
    /*-------------------------*/
    public static void main(String[] args) throws IOException, ClassNotFoundException, SQLException, Throwable {
        ServerSocket server = new ServerSocket(8080);
        System.out.println("Server Đang Chờ kết nối từ client...");

//        String serverSQL = "DESKTOP-6R4OPME\\MSSQL_EXP_2008R2";
//            String user = "sa";
//            String password = "6688701lll";
//            String db = "KIEMTRALTM";
//            int portSQL = 1433;
//            SQLServerDataSource ds = new SQLServerDataSource();
//            ds.setUser(user);
//            ds.setPassword(password);
//            ds.setDatabaseName(db);
//            ds.setServerName(serverSQL);
//            ds.setPortNumber(portSQL);
//            System.out.println(ds.getConnection().getCatalog());
        String pass = "", username;
        boolean flag = true;
        Connection connect = DBConection.getConnection();

        int result = 0;
        while(true) {
            Socket client = server.accept();
            System.out.println("Đã Thiết lập Kết Nối Thành Công !!!");
            // Nhan data tu sv
            DataInputStream din = new DataInputStream(client.getInputStream());
            // Gui data den sv
            DataOutputStream dout = new DataOutputStream(client.getOutputStream());
             int luaChon = din.readInt();
            switch (luaChon) {
                case 1: {
                    username = din.readUTF();
                    pass = din.readUTF();

                    String query = "	  SELECT *from dbo.login  where username=? and password=?";

                    PreparedStatement ps = connect.prepareStatement(query);
                    ps.setString(1, username);
                    ps.setString(2, pass);
                    ResultSet rs = ps.executeQuery();

                    if (rs.next()) {
                        dout.writeInt(-1);

                    } else {
                        dout.writeInt(-2);
                    }

                }
                break;
                case 2: {
                    String plaintext = din.readUTF();
                    String key = din.readUTF();

                    ServerTcp cipher = new ServerTcp(key);

                    String enc = cipher.getResult(plaintext, true);
                    //String dec = cipher.getResult(enc, false);
                    dout.writeUTF(enc);
                    //dout.writeUTF(dec);
                }
                break;
                case 3: {
                    String plaintext = din.readUTF();
                    String key = din.readUTF();

                    ServerTcp cipher = new ServerTcp(key);
 
                    String dec = cipher.getResult(plaintext, false);
                    //dout.writeUTF(enc);
                    dout.writeUTF(dec);
                }
                break;
                     case 4: {
                         String plaintext_file_input = din.readUTF();
                       FileInputStream fis = new FileInputStream(plaintext_file_input);
	FileOutputStream fos = new FileOutputStream(plaintext_file_input);
	                       
                 
                    String key = din.readUTF();
                     System.out.println(key);
                     encrypt(key, fis, fos);   
                    dout.writeUTF("thanh cong");
                }
                break;
            }
        }

    }
}
