package org.efurture.encrypt;

import java.nio.ByteBuffer;

public class Encrypt {


    public static void  cmd(String cmd, String args) {
        ByteBuffer api = ByteBuffer.allocateDirect(128);
        ByteBuffer method = ByteBuffer.allocateDirect(128);
        ByteBuffer params = ByteBuffer.allocateDirect(1024);
        ByteBuffer result = ByteBuffer.allocateDirect(4*1024);
    }

     private static native int doCmd(ByteBuffer api, ByteBuffer method, ByteBuffer params, ByteBuffer result);



}
