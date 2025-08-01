package org.efurture.encrypt;

public class Encrypt {

    static {
        System.load("/Users/baojian/code/gitflow/crossbuild/cmake-build-debug/libencrypt.dylib");
    }

    public static void  cmd(String cmd, String args) {
        doCmd(cmd, args);
    }

   private static native void doCmd(String cmd, String args);
}
