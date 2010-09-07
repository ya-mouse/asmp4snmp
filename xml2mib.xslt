<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:output method="text" indent="no"/>

<xsl:template match="/mib/node">
<xsl:value-of select="../@name"/> DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, IpAddress,
    enterprises
                             FROM SNMPv2-SMI
    InetAddress
                             FROM INET-ADDRESS-MIB;

<xsl:value-of select="@name"/> MODULE-IDENTITY
    LAST-UPDATED "201007280000Z"
    ORGANIZATION
       "Avocent"
    CONTACT-INFO
       "avocent@avocent.com"
    DESCRIPTION
       "Avocent"

    ::= { enterprises <xsl:value-of select="@id"/> }

UTF8String ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "255t"
    STATUS       current
    DESCRIPTION
        "UTF-8 String"
    SYNTAX OCTET STRING (SIZE (0..255))

<xsl:apply-templates select="node[@type='node']">
    <xsl:with-param name="parent" select="@name"/>
</xsl:apply-templates>
END
</xsl:template>

<xsl:template match="node">
    <xsl:param name="parent"/>

    <xsl:variable name="objects">
        <xsl:for-each select="node/@name">
            <xsl:if test="position()!=1">, </xsl:if><xsl:value-of select="."/>
        </xsl:for-each>
    </xsl:variable>

    <xsl:variable name="status">
        <xsl:choose>
            <xsl:when test="@status = 'unknown'">current</xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="@status"/>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:variable>

    <xsl:variable name="access">
        <xsl:choose>
            <xsl:when test="@accessibility='ro'">read-only</xsl:when>
            <xsl:when test="@accessibility='rw'">read-write</xsl:when>
            <xsl:otherwise>not-accessible</xsl:otherwise>
        </xsl:choose>
    </xsl:variable>

    <xsl:variable name="constraint">
        <xsl:for-each select="symbol"><xsl:if test="position()!=1">, </xsl:if><xsl:value-of select="@name"/>(<xsl:value-of select="@value"/>)</xsl:for-each>
    </xsl:variable>

    <xsl:choose>
        <xsl:when test="@type = 'node' or @type = 'sequenceOfType'">
            <xsl:call-template name="print-node">
                <xsl:with-param name="parent" select="$parent"/>
                <xsl:with-param name="objects" select="$objects"/>
                <xsl:with-param name="status">current</xsl:with-param>
                <xsl:with-param name="access"/>
                <xsl:with-param name="type">GROUP</xsl:with-param>
                <xsl:with-param name="syntax"/>
            </xsl:call-template>
        </xsl:when>
        <xsl:when test="@type = 'int'">
            <xsl:call-template name="print-node">
                <xsl:with-param name="parent" select="$parent"/>
                <xsl:with-param name="objects" select="$objects"/>
                <xsl:with-param name="status" select="$status"/>
                <xsl:with-param name="access" select="$access"/>
                <xsl:with-param name="type">TYPE</xsl:with-param>
                <xsl:with-param name="syntax">INTEGER <xsl:if test="$constraint != ''">{ <xsl:value-of select="$constraint"/> }</xsl:if></xsl:with-param>
            </xsl:call-template>
        </xsl:when>
        <xsl:when test="@type = 'ipAddress'">
            <xsl:call-template name="print-node">
                <xsl:with-param name="parent" select="$parent"/>
                <xsl:with-param name="objects" select="$objects"/>
                <xsl:with-param name="status" select="$status"/>
                <xsl:with-param name="access" select="$access"/>
                <xsl:with-param name="type">TYPE</xsl:with-param>
                <xsl:with-param name="syntax">IpAddress</xsl:with-param>
            </xsl:call-template>
        </xsl:when>
        <xsl:when test="@type = 'ascii' or @type = 'utf8' or @type = 'byte[]'">
            <xsl:call-template name="print-node">
                <xsl:with-param name="parent" select="$parent"/>
                <xsl:with-param name="objects" select="$objects"/>
                <xsl:with-param name="status" select="$status"/>
                <xsl:with-param name="access" select="$access"/>
                <xsl:with-param name="type">TYPE</xsl:with-param>
                <xsl:with-param name="syntax">
                    <xsl:choose>
                        <xsl:when test="@typeSymbol!=''">
                            <xsl:value-of select="@typeSymbol"/>
                        </xsl:when>
                        <xsl:otherwise>OCTET STRING</xsl:otherwise>
                    </xsl:choose>
                </xsl:with-param>
            </xsl:call-template>
        </xsl:when>
    </xsl:choose>
</xsl:template>

<xsl:template name="print-node">
    <xsl:param name="parent"/>
    <xsl:param name="objects"/>
    <xsl:param name="status"/>
    <xsl:param name="access"/>
    <xsl:param name="syntax"/>
    <xsl:param name="type"/>

<xsl:value-of select="@name"/> OBJECT-<xsl:value-of select="$type"/>
    <xsl:if test="$objects != ''">&#xA;    OBJECTS { <xsl:value-of select="$objects"/> }</xsl:if>
    <xsl:if test="$syntax != ''">&#xA;    SYNTAX <xsl:value-of select="$syntax"/></xsl:if>
    <xsl:if test="$access != ''">&#xA;    MAX-ACCESS <xsl:value-of select="$access"/></xsl:if>
    STATUS <xsl:value-of select="$status"/>
    DESCRIPTION
        "<xsl:value-of select="@name"/>"
    ::= { <xsl:value-of select="$parent"/> <xsl:text> </xsl:text> <xsl:value-of select="@id"/> }

<xsl:apply-templates select="node">
    <xsl:with-param name="parent" select="@name"/>
</xsl:apply-templates>

</xsl:template>

</xsl:stylesheet>
