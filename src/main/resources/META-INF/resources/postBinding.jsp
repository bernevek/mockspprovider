<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
    <head>
        <title>Post-Binding</title>
    </head>
    <body onload="">
        <div>
            <form action="${PostBindingLink}"
                  method="post" name="postBinding">
                <div>
                    <c:if test="${not empty RelayState}">
                        <input type="hidden" name="RelayState" value="${RelayState}"/>
                    </c:if>
                    <c:if test="${not empty SigAlg}">
                        <input type="hidden" name="SigAlg" value="${SigAlg}"/>
                    </c:if>
                    <c:if test="${not empty Signature}">
                        <input type="hidden" name="Signature" value="${Signature}"/>
                    </c:if>
                    <c:if test="${not empty SAMLRequest}">
                        <input type="hidden" name="SAMLRequest" value="${SAMLRequest}"/>
                    </c:if>
                </div>
                <%--<div>--%>
                    <%--<input type="submit" value="Login"/>--%>
                <%--</div>--%>
            </form>
        </div>
    <script>
        window.onload = function(){
            document.forms['postBinding'].submit();
        }
    </script>
    </body>
</html>
