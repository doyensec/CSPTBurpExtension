package com.doyensec.ClientSidePathTraversal;

import java.util.Objects;

public class PotentialSink {

    String url;
    String method;

    public PotentialSink(String method, String url) {
        this.url = url;
        this.method = method;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        PotentialSink that = (PotentialSink) o;

        // Only check sink based on the most restrictive values(url and method)
        return Objects.equals(url, that.url) && Objects.equals(method, that.method);
    }

    @Override
    public int hashCode() {
        return Objects.hash(url, method);
    }
}
