<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Responce</title>
</head>
<body>
<div>
    <c:choose>
        <c:when test="${SpSessionDeleted==true}">
            <div>SP session is terminated</div>
        </c:when>
        <c:otherwise>
            <div>Logged in with SP session</div>
            <a href="/terminateSpSession">Terminate SP session</a>
        </c:otherwise>
    </c:choose>
</div>
</body>
</html>
