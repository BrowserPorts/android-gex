import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;

// What art.sh runs: recursion, collections, a lambda, string building, a
// thread, a caught exception and formatting, each printing what it made.
public class Hello {
    static int fib(int n) {
        return n < 2 ? n : fib(n - 1) + fib(n - 2);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("hello from art");
        System.out.println("fib(25) = " + fib(25));
        ArrayList<String> l = new ArrayList<>();
        for (String s : new String[] {"pear", "apple", "fig"}) l.add(s);
        Collections.sort(l);
        System.out.println(l);
        HashMap<String, Integer> m = new HashMap<>();
        for (int i = 0; i < 1000; i++) m.merge("k" + (i % 7), i, Integer::sum);
        System.out.println(m.get("k3"));
        StringBuilder sb = new StringBuilder();
        for (char c = 'a'; c <= 'e'; c++) sb.append(c).append(c - 'a');
        System.out.println(sb);
        Thread t = new Thread(() -> System.out.println("thread " + Thread.currentThread().getName()));
        t.setName("worker");
        t.start();
        t.join();
        try {
            Object o = null;
            o.toString();
        } catch (NullPointerException e) {
            System.out.println("caught npe");
        }
        System.out.println(String.format("%.3f %x", Math.sqrt(2.0), 255));
        System.out.println(System.getProperty("java.vm.name") != null);
    }
}
