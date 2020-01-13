<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Responce</title>
</head>
<body>
<div>
    <c:if test="${not empty SAMLResponse}">
        <div>SAMLresponce</div>
        <textarea id="SAMLResponse" rows="40" cols="100" readonly>${SAMLResponse}</textarea>
    </c:if>
    <c:if test="${not empty SigAlg}">
        <div>SigAlg</div>
        <textarea id="SigAlg" rows="2" cols="100" readonly>${SigAlg}</textarea>
    </c:if>
    <c:if test="${not empty Signature}">
        <div>Signature</div>
        <textarea id="SAMLResponse" rows="10" cols="100" readonly>${Signature}</textarea>
    </c:if>
</div>
</body>
</html>
