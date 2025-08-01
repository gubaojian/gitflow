package org.efurture.encrypt;

public class Encrypt {

    static {
        System.loadLibrary("encrypt");
    }

    public static void  cmd(String cmd, String args) {
        doCmd(cmd, args);
    }

   private static native void doCmd(String cmd, String args);
}
