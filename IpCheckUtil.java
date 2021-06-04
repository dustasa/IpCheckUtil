package com.decard.launchsettings.utils;

import android.util.Log;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.Integer.parseInt;

public class IpCheckUtil {
    private static String TAG = "IPCheckUtil";
    private static String ipv4_class_a = "ClassA";
    private static String ipv4_class_b = "ClassB";
    private static String ipv4_class_c = "ClassC";
    private static String ipv4_class_err = "error";

    // 检测输入IP是否合法
    public static Boolean checkIp(String ipAdd)  {
        Boolean isLegal = false;
        isLegal = isIpAddress(ipAdd);
        Log.d(TAG,"Ip address is: "+ipAdd);
        if (isLegal) {
            Log.d(TAG,"Ip address legal");
            return true;
        } else {
            Log.d(TAG,"Ip address illegal");
            return false;
        }
    }

    // 检测输入网关是否合法
    public static Boolean checkGateway(String gatewayAdd) {
        Boolean isLegal = false;
        isLegal = isIpAddress(gatewayAdd);
        Log.d(TAG,"Gateway address is: "+gatewayAdd);
        if (isLegal) {
            Log.d(TAG,"gateway address legal");
            return true;
        } else {
            Log.d(TAG,"gateway address illegal");
            return false;
        }
    }

    // 检测输入子网掩码是否合法
    public static Boolean checkMask(String maskAdd) {
        Boolean isLegal = false;
        isLegal = isIpAddress(maskAdd);
        Log.d(TAG,"Mask address is: "+maskAdd);
        if (isLegal) {
            Log.d(TAG,"mask address legal");
            return true;
        } else {
            Log.d(TAG,"mask address illegal");
            return false;
        }
    }

    // 检测输入DNS是否合法
    public static Boolean checkDNS(String dnsAdd) {
        Boolean isLegal = false;
        isLegal = isIpAddress(dnsAdd);
        Log.d(TAG,"DNS address is: "+dnsAdd);
        if (isLegal) {
            Log.d(TAG,"dns address legal");
            return true;
        } else {
            Log.d(TAG,"dns address illegal");
            return false;
        }
    }

    // 检测输入的IP、网关、子网掩码、DNS是否配套且合法
    public static Boolean checkStaticIpConfig(String ipAdd, String gatewayAdd, String maskAdd, String dnsAdd) {
        String ip_class = "";
        if (isIpAddress(ipAdd) && isIpAddress(gatewayAdd) && isIpAddress(gatewayAdd) && isIpAddress(dnsAdd)) {
            Log.d(TAG,"static ip config legal,go to check whether it is matched.");
            ip_class = innerIP(ipAdd);
            Log.d(TAG, "ip belongs-> "+ip_class);
            if (ip_class.equals(ipv4_class_a)) {
                // 判断网关是否和配置的ip地址在同一网段
                return gateCompareIp(ipAdd,gatewayAdd,maskAdd);
            } else if (ip_class.equals(ipv4_class_b)) {
                return gateCompareIp(ipAdd,gatewayAdd,maskAdd);
            } else if (ip_class.equals(ipv4_class_c)) {
                return gateCompareIp(ipAdd,gatewayAdd,maskAdd);
            } else if (ip_class.equals(ipv4_class_err)) {
                return false;
            } else {
                return false;
            }
        } else  {
            Log.d(TAG,"static ip config illegal");
            return false;
        }
    }

    // 判断是否是IP地址
    private static Boolean isIpAddress(String ip) {
        boolean result = false;
        if (ip != null || !ip.isEmpty() | ip.length()<16){

            // 定义正则表达式
            // 字段只有1位时：只能是1-9中的一个数字[1-9]
            // 字段有2位时：开头不能是0，所以开头数字是1-9[1-9]，而个位数字可以是0-9[0-9]
            // 字段3位时: 百位是1：十位和个位没有要求 1\\d\\d
            //           百位是2：十分位只能是 0-4[0-4]，个位无要求\\d
            //           百位、十位分别是2、5，则个位只能是0-5   25[0-5]
            // 前三位要记得后面加一个.   \\.
            String regex = "([1-9]|[1-9][0-9]|1\\d\\d|2[0-4]\\d|25[0-5])\\." +
                    "([1-9]|[1-9][0-9]|1\\d\\d|2[0-4]\\d|25[0-5])\\." +
                    "([1-9]|[1-9][0-9]|1\\d\\d|2[0-4]\\d|25[0-5])\\." +
                    "([1-9]|[1-9][0-9]|1\\d\\d|2[0-4]\\d|25[0-5])";

            result =  Pattern.matches(regex,ip);

        }
        return result;
    }

    // 判断是否是内网地址，并返回ipv4地址分类
    // class A: 10.0.0.0 - 10.255.255.255
    // class B: 172.16.0.0 - 172.31.255.255
    // class C: 192.168.0.0 - 192.168.255.255
    public static String innerIP(String ip) {

        //匹配10.0.0.0 - 10.255.255.255的网段
        String pattern_class_A = "^(\\D)*10(\\.([2][0-4]\\d|[2][5][0-5]|[01]?\\d?\\d)){3}";

        //匹配172.16.0.0 - 172.31.255.255的网段
        String pattern_class_B = "172\\.([1][6-9]|[2]\\d|3[01])(\\.([2][0-4]\\d|[2][5][0-5]|[01]?\\d?\\d)){2}";

        //匹配192.168.0.0 - 192.168.255.255的网段
        String pattern_class_C = "192\\.168(\\.([2][0-4]\\d|[2][5][0-5]|[01]?\\d?\\d)){2}";

        //合起来写
        String pattern = "((192\\.168|172\\.([1][6-9]|[2]\\d|3[01]))"
                + "(\\.([2][0-4]\\d|[2][5][0-5]|[01]?\\d?\\d)){2}|"
                + "^(\\D)*10(\\.([2][0-4]\\d|[2][5][0-5]|[01]?\\d?\\d)){3})";

        Pattern reg_a = Pattern.compile(pattern_class_A);
        Matcher match_a = reg_a.matcher(ip);

        Pattern reg_b = Pattern.compile(pattern_class_B);
        Matcher match_b = reg_b.matcher(ip);

        Pattern reg_c = Pattern.compile(pattern_class_C);
        Matcher match_c = reg_c.matcher(ip);

        if (match_a.find()) {
            return ipv4_class_a;
        } else if(match_b.find()){
            return ipv4_class_b;
        } else if (match_c.find()) {
            return ipv4_class_c;
        } else {
            return ipv4_class_err;
        }
    }

    // 判断网关是否和配置的ip地址在同一网段
    private static boolean gateCompareIp(String ipAdd, String gateAdd, String maskAdd) {
        String ipAddTmpArr[];
        String gateAddTmpArr[];
        String maskAddTmpArr[];
        // 以 "."为分隔符分割ip地址
        ipAddTmpArr = ipAdd.split("\\.");
        gateAddTmpArr = gateAdd.split("\\.");
        maskAddTmpArr = maskAdd.split("\\.");
//        for (int i=0; i< ipAddTmpArr.length;i++) {
//            Log.d(TAG,"ipAddTmpArr "+ i +" is: "+ipAddTmpArr[i]);
//            Log.d(TAG,"gateAddTmpArr "+ i +" is: "+gateAddTmpArr[i]);
//            Log.d(TAG,"maskAddTmpArr "+ i +" is: "+maskAddTmpArr[i]);
//        }
        // ip地址和子网掩码做与运算
        int res0 = parseInt(ipAddTmpArr[0]) & parseInt(maskAddTmpArr[0]);
        int res1 = parseInt(ipAddTmpArr[1]) & parseInt(maskAddTmpArr[1]);
        int res2 = parseInt(ipAddTmpArr[2]) & parseInt(maskAddTmpArr[2]);
        int res3 = parseInt(ipAddTmpArr[3]) & parseInt(maskAddTmpArr[3]);
//        Log.d(TAG,"res 0 is: "+res0);
//        Log.d(TAG,"res 1 is: "+res1);
//        Log.d(TAG,"res 2 is: "+res2);
//        Log.d(TAG,"res 3 is: "+res3);
        // 网关地址和子网掩码做与运算
        int res0_gw = parseInt(gateAddTmpArr[0]) & parseInt(maskAddTmpArr[0]);
        int res1_gw = parseInt(gateAddTmpArr[1]) & parseInt(maskAddTmpArr[1]);
        int res2_gw = parseInt(gateAddTmpArr[2]) & parseInt(maskAddTmpArr[2]);
        int res3_gw = parseInt(gateAddTmpArr[3]) & parseInt(maskAddTmpArr[3]);
//        Log.d(TAG,"res gw 0 is: "+res0_gw);
//        Log.d(TAG,"res gw 1 is: "+res1_gw);
//        Log.d(TAG,"res gw 2 is: "+res2_gw);
//        Log.d(TAG,"res gw 3 is: "+res3_gw);

        if (res0==res0_gw && res1==res1_gw && res2==res2_gw && res3==res3_gw) {
            Log.d(TAG,"IP地址与子网掩码、网关地址匹配");
            return true;
        } else {
            Log.e(TAG,"IP地址与子网掩码、网关地址不匹配！！");
            return false;
        }
    }
}
