package biz.gomsoft.cesadminweb.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhncorp.lucy.security.xss.XssPreventer;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

import java.io.*;
import java.util.*;

// JSON body 를 가진 http 요청 올 때 미리 xss 필터링 하는 필터
// https://naver.github.io/lucy-xss-filter/kr/
// https://programforlife.tistory.com/116
// https://www.baeldung.com/java-jsonnode-get-keys

@Slf4j
public class SimpleIncomingXssFilter extends HttpServletRequestWrapper {
    private byte[] rawData;

    public SimpleIncomingXssFilter(HttpServletRequest request) {
        super(request);

        try {
            // JSON 은 바로 변환한다
            if(request.getMethod().equalsIgnoreCase("post") && (request.getContentType().equals("application/json") || request.getContentType().equals("multipart/form-data"))) {
                InputStream is = request.getInputStream();
                final int length = request.getContentLength();
                byte[] temp = is.readAllBytes();
                if(length != temp.length)
                    throw new IOException("요청 데이터를 읽지 못했습니다.");

                this.rawData = replaceJsonXSS(temp);
            }
        } catch (Exception e) {
            log.error("Error reading the request body", e);
        }
    }

    public String getKeysInJsonUsingMaps(String sourceJsonBody, ObjectMapper mapper) throws JsonMappingException, JsonProcessingException {
        Map<String, Object> jsonElements = mapper.readValue(sourceJsonBody, new TypeReference<Map<String, Object>>() {
        });
        traverseAll(jsonElements);
        return mapper.writeValueAsString(jsonElements);
    }

    private void traverseAll(Map<String, Object> jsonElements) {

        jsonElements.entrySet()
                .forEach(entry -> {
                    if (entry.getValue() instanceof Map) {
                        Map<String, Object> map = (Map<String, Object>) entry.getValue();
                        traverseAll(map);
                    } else if (entry.getValue() instanceof List) {
                        List<?> list = (List<?>) entry.getValue();
                        list.forEach(listEntry -> {
                            if (listEntry instanceof Map) {
                                Map<String, Object> map = (Map<String, Object>) listEntry;
                                traverseAll(map);
                            }
                        });
                    }else if(entry.getValue() instanceof String) {  // text
                        String replaced = XssPreventer.escape((String)entry.getValue());
                        log.debug("replacing xss: {} -> {}", entry.getValue(), replaced);
                        entry.setValue(replaced);
                    }
                });
    }
    //바이트 단위 script 태그 치환
    private byte[] replaceJsonXSS(byte[] data) throws IOException {
        String strData = new String(data);

        String replaced = getKeysInJsonUsingMaps(strData, new ObjectMapper());
        return replaced.getBytes();
    }

    //문자열 단위 script 태그 치환
    private String replaceXSS(String value) {
        if(value != null) {
            return XssPreventer.escape(value);
        }
        return value;
    }


    @Override
    public ServletInputStream getInputStream() throws IOException {
        log.debug(("getInputStream"));
        if(this.rawData == null) {
            log.debug("rawData is null");
            return super.getInputStream();
        }
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.rawData);

        return new ServletInputStream() {

            @Override
            public int read() throws IOException {
                // TODO Auto-generated method stub
                return byteArrayInputStream.read();
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // TODO Auto-generated method stub
            }

            @Override
            public boolean isReady() {
                // TODO Auto-generated method stub
                return false;
            }

            @Override
            public boolean isFinished() {
                // TODO Auto-generated method stub
                return false;
            }
        };
    }

    @Override
    public String getQueryString() {
        return replaceXSS(super.getQueryString());
    }

    @Override
    public String getParameter(String name) {
        return replaceXSS(super.getParameter(name));
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        Map<String, String[]> params = super.getParameterMap();
        if(params != null) {
            params.forEach((key, value) -> {
                for(int i=0; i<value.length; i++) {
                    value[i] = replaceXSS(value[i]);
                }
            });
        }
        return params;
    }

    @Override
    public String[] getParameterValues(String name) {
        String[] params = super.getParameterValues(name);
        if(params != null) {
            for(int i=0; i<params.length; i++) {
                params[i] = replaceXSS(params[i]);
            }
        }
        return params;
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(this.getInputStream(), "UTF-8"));
    }

    @Bean
    public FilterRegistrationBean<CustomXssFilter> xssFilter() {

        FilterRegistrationBean<CustomXssFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new CustomXssFilter());
        /*
        registrationBean.addUrlPatterns("/url/urlPattern1",
                "/url/urlPattern2",
                "/url/urlPattern3",
                "/url/urlPattern4",
                "/url/urlPattern5",
                "/url2/urlPattern1",
                "/url2/urlPattern2");
        */
        return registrationBean;
    }
}
