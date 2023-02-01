from bs4 import BeautifulSoup
import requests

import requests
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4.diagnose import diagnose

from urllib.parse import urljoin
import urllib.parse
import json


class Scanner:

    def __init__(self, url, ignore_links):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []
        self.links_to_ignore = ignore_links

    def extract_links_from(self, url):
        # resp = self.session.get(url)
        html = requests.get(url)

        soupencode = BeautifulSoup(html.content, "html.parser")

        # encoded method
        encode = soupencode.original_encoding
        try:
            soup = BeautifulSoup(html.content.decode(encoding=encode), "html.parser")
            enc = soup.original_encoding
            url_founded = re.findall('(?:href=")(.*?)"', soup.prettify())
            #print(url_founded)
            return url_founded
        except:
            soup = BeautifulSoup(html.content.decode(encoding="ISO-8859-1"), "html.parser")
            url_founded = re.findall('(?:href=")(.*?)"', soup.prettify())
            #print(url_founded)
            return url_founded

    def crawl(self, url=None):
        if url == None:
            url = self.target_url
        print("Buscando Links - Realizando Crawling")
        href_links = self.extract_links_from(url)

        for link in href_links:
            link = urllib.parse.urljoin(url, link)

            if "#" in link:
                link = link.split("#")[0]

            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                # Ignore logout url
                self.target_links.append(link)
                self.crawl(link)

    def extract_forms(self, url):
        response = requests.get(url)
        # parse the contentes of the page

        soup = BeautifulSoup(response.content, "html.parser")

        # encoded method
        encode = soup.original_encoding
        try:
            parsed_html = BeautifulSoup(response.content.decode(encoding=encode), "html.parser")
            print(parsed_html.findAll("form"))
            return parsed_html.findAll("form")
        except:
            parsed_html = BeautifulSoup(response.content.decode(encoding="ISO-8859-1"), "html.parser")
            #print(parsed_html.findAll("form"))
            return parsed_html.findAll("form")

    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urllib.parse.urljoin(url, action)
        method = form.get("method")

        inputs_list = form.findAll("input")
        post_data = {}

        for input in inputs_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            if input_type == "text":
                input_value = value

            post_data[input_name] = input_value
        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def run_scanner(self):
        saida = []
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                #print("teste form " + str(form))
                print("[+] Testing form in " + link)
                is_vulnerable_to_xss = self.test_xss_in_form(form, link)
                if is_vulnerable_to_xss:
                    print("XSS EM FORM")
                    saida.append({'vulnerabilidade': 'xss', 'url': link,
                                  'conteudo': 'É um tipo de vulnerabilidade que tem como intuito injetar códigos JavaScript em uma aplicação, com intuito de coletar dados ou até mesmo manipular requisições que o usuário está realizando.',
                                  'recomendacao': 'Como recomendação, para proteger a aplicação de ataques de injeção, deve fazer o tratamento dos dados recebidos e enviados pela aplicação, sendo assim fazendo uma validação dos dados que entram e dos dados que são enviados pela aplicação, para estas validações pode se adotar a utilização de expressão regulares, blacklists entre outras alternativas.',
                                  'referencias': 'https://owasp.org/www-community/attacks/xss/'})
                if_vulnerabel_sql = self.test_sql_injection_form(form, link)
                if (if_vulnerabel_sql):
                    print("SQL EM FORM")
                    saida.append({'vulnerabilidade': 'SQL Injection', 'url': link,
                                  'conteudo': 'É um tipo de vulnerabilidade que permite a injeção de comendos SQL para se comunicar com o banco de dados, com o objetivo de coletar e manipular dados ou até mesmo causar indisponibilidade na aplicação.',
                                  'recomendacao': 'Como recomendação, para proteger a aplicação de ataques de injeção, deve fazer o tratamento dos dados recebidos e enviados pela aplicação, sendo assim fazendo uma validação dos dados que entram e dos dados que são enviados pela aplicação, para estas validações pode se adotar a utilização de expressão regulares, blacklists entre outras alternativas.',
                                  'referencias': 'https://owasp.org/www-community/attacks/SQL_Injection'})

            #if "=" in link:
            print("[+] Testing " + link)
            if_vulnerable_to_xss = self.test_xss_in_link(link)
            if if_vulnerable_to_xss:
                print("XSS EM LINK")
                saida.append({'vulnerabilidade': 'xss', 'url': link,
                                  'conteudo': 'É um tipo de vulnerabilidade que tem como intuito injetar códigos JavaScript em uma aplicação, com intuito de coletar dados ou até mesmo manipular requisições que o usuário está realizando.',
                                  'recomendacao': 'Como recomendação, para proteger a aplicação de ataques de injeção, deve fazer o tratamento dos dados recebidos e enviados pela aplicação, sendo assim fazendo uma validação dos dados que entram e dos dados que são enviados pela aplicação, para estas validações pode se adotar a utilização de expressão regulares, blacklists entre outras alternativas.',
                                  'referencias': 'https://owasp.org/www-community/attacks/xss/'})
            if_vulnerabel_sql = self.test_sql_injection(link)
            if if_vulnerabel_sql ==  True:
                print("SQL EM LINK")
                saida.append({'vulnerabilidade': 'SQL Injection', 'url': link,
                                  'conteudo': 'É um tipo de vulnerabilidade que permite a injeção de comendos SQL para se comunicar com o banco de dados, com o objetivo de coletar e manipular dados ou até mesmo causar indisponibilidade na aplicação.',
                                  'recomendacao': 'Como recomendação, para proteger a aplicação de ataques de injeção, deve fazer o tratamento dos dados recebidos e enviados pela aplicação, sendo assim fazendo uma validação dos dados que entram e dos dados que são enviados pela aplicação, para estas validações pode se adotar a utilização de expressão regulares, blacklists entre outras alternativas.',
                                  'referencias': 'https://owasp.org/www-community/attacks/SQL_Injection'})

        return saida

    def test_xss_in_link(self, url):
        xss_test_script = "<sCript>alert('test')</scriPt>"
        url = url.replace("=", "=" + xss_test_script)
        response = self.session.get(url)
        return xss_test_script.encode() in response.content

    def test_xss_in_form(self, form, url):
        xss_test_script = "<sCript>alert('test')</scriPt>"
        response = self.submit_form(form, xss_test_script, url)
        return xss_test_script.encode() in response.content

    def test_sql_injection(self, url):
        sql_test_script = "'"
        url = url.replace("=", "=" + sql_test_script)
        response = self.session.get(url)
        errors = ['You have an error in your SQL syntax', 'mysql', 'ldap_root_password',
                  'MariaDB server version for the right syntax', 'MariaDB', 'mysql error', 'mysql_fetch_array',
                  'mysql_fetch', 'ORA-', 'Oracle', 'PostgreSql Error', 'postigreSQL']
        texto = "crawciscan"
        for i in errors:
            str(i)
            if (i.encode() in response.content):
                #print(texto.encode() in response.content)
                return i.encode() in response.content
        #print(texto.encode() in response.content)
        return texto.encode() in response.content


    def test_sql_injection_form(self, form, url):
        sql_test_script = "'"
        response = self.submit_form(form, sql_test_script, url)

        errors = ['You have an error in your SQL syntax', 'mysql', 'ldap_root_password',
                  'MariaDB server version for the right syntax', 'MariaDB', 'mysql error', 'mysql_fetch_array',
                  'mysql_fetch', 'ORA-', 'Oracle', 'PostgreSql Error', 'postigreSQL']

        texto = "crawciscan"
        for i in errors:
            str(i)
            if (i.encode() in response.content):
                return i.encode() in response.content
        return texto.encode() in response.content


