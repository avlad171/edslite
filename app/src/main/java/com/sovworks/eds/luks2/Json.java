package com.sovworks.eds.luks2;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal strict JSON parser for LUKS2 metadata (untrusted input).
 * Objects -> LinkedHashMap, arrays -> ArrayList, strings -> String,
 * numbers -> Long (integers only; LUKS2 uses no fractions), true/false -> Boolean, null -> NULL.
 * Rejects duplicate keys, trailing garbage, excessive nesting and non-integer numbers.
 */
public final class Json
{
    public static final Object NULL = new Object() { @Override public String toString() { return "null"; } };

    public static class JsonException extends Luks2Exception
    {
        JsonException(String msg, int pos) { super("JSON: " + msg + " at offset " + pos); }
    }

    private static final int MAX_DEPTH = 32;

    public static Object parse(String s) throws JsonException
    {
        Json p = new Json(s);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.i != s.length())
            throw new JsonException("trailing data", p.i);
        return v;
    }

    private final String s;
    private int i;

    private Json(String s) { this.s = s; }

    private Object value(int depth) throws JsonException
    {
        if (depth > MAX_DEPTH)
            throw new JsonException("nesting too deep", i);
        if (i >= s.length())
            throw new JsonException("unexpected end", i);
        char c = s.charAt(i);
        switch (c)
        {
            case '{': return object(depth);
            case '[': return array(depth);
            case '"': return string();
            case 't': lit("true"); return Boolean.TRUE;
            case 'f': lit("false"); return Boolean.FALSE;
            case 'n': lit("null"); return NULL;
            default:
                if (c == '-' || (c >= '0' && c <= '9'))
                    return number();
                throw new JsonException("unexpected character '" + c + "'", i);
        }
    }

    private Map<String, Object> object(int depth) throws JsonException
    {
        Map<String, Object> m = new LinkedHashMap<>();
        i++; ws();
        if (peek() == '}') { i++; return m; }
        while (true)
        {
            ws();
            if (peek() != '"')
                throw new JsonException("expected key", i);
            String k = string();
            ws(); expect(':'); ws();
            if (m.containsKey(k))
                throw new JsonException("duplicate key \"" + k + "\"", i);
            m.put(k, value(depth + 1));
            ws();
            char c = next();
            if (c == '}') return m;
            if (c != ',') throw new JsonException("expected , or }", i - 1);
        }
    }

    private List<Object> array(int depth) throws JsonException
    {
        List<Object> a = new ArrayList<>();
        i++; ws();
        if (peek() == ']') { i++; return a; }
        while (true)
        {
            ws();
            a.add(value(depth + 1));
            ws();
            char c = next();
            if (c == ']') return a;
            if (c != ',') throw new JsonException("expected , or ]", i - 1);
        }
    }

    private String string() throws JsonException
    {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true)
        {
            char c = next();
            if (c == '"') return b.toString();
            if (c < 0x20) throw new JsonException("control character in string", i - 1);
            if (c != '\\') { b.append(c); continue; }
            char e = next();
            switch (e)
            {
                case '"': case '\\': case '/': b.append(e); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case 'n': b.append('\n'); break;
                case 'r': b.append('\r'); break;
                case 't': b.append('\t'); break;
                case 'u':
                    if (i + 4 > s.length()) throw new JsonException("bad \\u escape", i);
                    try { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); }
                    catch (NumberFormatException ex) { throw new JsonException("bad \\u escape", i); }
                    i += 4;
                    break;
                default: throw new JsonException("bad escape", i - 1);
            }
        }
    }

    private Long number() throws JsonException
    {
        int st = i;
        if (peek() == '-') i++;
        while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
        if (i < s.length() && ".eE".indexOf(s.charAt(i)) >= 0)
            throw new JsonException("non-integer number", i);
        try { return Long.parseLong(s.substring(st, i)); }
        catch (NumberFormatException ex) { throw new JsonException("bad number", st); }
    }

    private void lit(String w) throws JsonException
    {
        if (!s.startsWith(w, i)) throw new JsonException("bad literal", i);
        i += w.length();
    }

    private void ws() { while (i < s.length() && " \t\r\n".indexOf(s.charAt(i)) >= 0) i++; }
    private char peek() throws JsonException { if (i >= s.length()) throw new JsonException("unexpected end", i); return s.charAt(i); }
    private char next() throws JsonException { char c = peek(); i++; return c; }
    private void expect(char c) throws JsonException { if (next() != c) throw new JsonException("expected '" + c + "'", i - 1); }
}
