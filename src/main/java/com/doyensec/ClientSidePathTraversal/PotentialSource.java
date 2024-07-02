package com.doyensec.ClientSidePathTraversal;

import java.util.Objects;

public class PotentialSource {
  final String paramName;
  final String paramValue;
  final String sourceURL;

  public PotentialSource(String paramName, String paramValue, String sourceURL) {
    this.paramName = paramName;
    this.paramValue = paramValue;
    this.sourceURL = sourceURL;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    PotentialSource that = (PotentialSource) o;

    // Source is a combination of a url and param
    return Objects.equals(paramName, that.paramName)
        && Objects.equals(paramValue, that.paramValue)
        && Objects.equals(sourceURL, that.sourceURL);
  }

  @Override
  public int hashCode() {
    return Objects.hash(paramName, paramValue, sourceURL);
  }
}
