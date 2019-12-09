# -*- coding: utf-8 -*-
import enum
from datetime import datetime
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# from app.api.constants import complex_excel_sql

db = SQLAlchemy(session_options={"autocommit": False})


class ArchitectureEnum(enum.Enum):
    x86 = "x86"
    x64 = "x64"


class ConfigBase(db.Model):
    __abstract__ = True
    __public__ = ["name", "host", "user", "db_name"]
    id = db.Column(db.Integer, primary_key=True, comment="编号")
    name = db.Column(db.String(128), nullable=False, index=True, comment="名称")
    host = db.Column(db.String(256), nullable=False, comment="主机/IP")
    port = db.Column(db.Integer, nullable=False, default=3306, comment="端口")
    user = db.Column(db.String(128), nullable=False, comment="用户名")
    pwd = db.Column(db.String(256), nullable=False, comment="密码")
    db_name = db.Column(db.String(64), nullable=True, comment="数据库名")
    table_name = db.Column(db.String(64), nullable=True, comment="表名")
    description = db.Column(db.Text(2048), nullable=True, comment="描述")
    add_time = db.Column(db.DateTime(), nullable=True, default=datetime.now, comment="生成时间")

    def __init__(self, name, host, user, pwd, db_name, port):
        self.name = name
        self.host = host
        self.user = user
        self.pwd = pwd
        self.port = port
        self.db_name = db_name

    def __repr__(self):
        return self.name

    def to_dict(self):
        obj_dict = {}
        for i, j in self._sa_instance_state.attrs.items():
            if i in self.__public__:
                obj_dict[i] = j.value
        return obj_dict


class UserProfile(UserMixin, db.Model):
    __tablename__ = "vul_user"
    id = db.Column(db.Integer, primary_key=True, comment="编号")
    username = db.Column(db.String(24), unique=True, nullable=False, index=True, comment="用户名")
    _password = db.Column(db.String(128), unique=True, nullable=False, index=True, comment="密码")
    role = db.Column(db.Enum("admin", "translator", "pr_editor"), nullable=False, )

    def __init__(self, name, password, role="admin"):
        self.username = name
        self.password = password
        self.role = role

    def __repr__(self):
        return self.username

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, raw_pass):
        self._password = generate_password_hash(raw_pass)

    def check_password(self, raw_pass):
        return check_password_hash(self.password, raw_pass)

    @property
    def is_admin(self):
        if self.role == "admin":
            return True


class Advisory(db.Model):
    __tablename__ = "vul_advisory"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, comment="id标识")
    aid = db.Column(db.String(24), index=True, unique=True, comment="公告标识")
    title = db.Column(db.String(256), nullable=False, comment="原标题")
    translated_title = db.Column(db.String(256), default="", nullable=False, comment="翻译标题")
    link = db.Column(db.String(256), nullable=False, comment="链接")
    advisory_body = db.Column(db.Text, nullable=True, comment="通告内容")
    description = db.Column(db.Text, nullable=True, comment="详细信息")
    translation = db.Column(db.Text, nullable=True, comment="详情译文")
    cves = db.Column(db.Text, nullable=True, comment="相关CVE")
    affect_versions = db.Column(db.Text, nullable=True, comment="影响版本")
    pub_date = db.Column(db.Date(), nullable=False, comment="发布时间")
    record_time = db.Column(db.DateTime, default=datetime.now(), comment="记录时间")
    is_translated = db.Column(db.Boolean, default=False, comment="审核状态")
    advisory_type = db.Column(db.SmallInteger, default=1, comment="公告类型")
    gmt_modified = db.Column(db.DateTime, default=datetime.now, comment="更新时间")
    tags = db.Column(db.Text, nullable=True, comment="类型(中文)")
    tags_en = db.Column(db.Text, nullable=True, comment="类型(英文)")
    comment = "公告信息"

    def __init__(self, aid, title, link, pub_date, advisory="", description="", translation="", advisory_body="",
                 advisory_type=1, translated_title="", cves="", affect_versions="", is_translated=False):
        self.aid = aid
        self.title = title
        self.link = link
        self.pub_date = pub_date
        self.advisory = advisory
        self.description = description
        self.translation = translation
        self.advisory_type = advisory_type
        self.translated_title = translated_title
        self.is_translated = is_translated
        self.affect_versions = affect_versions
        self.advisory_body = advisory_body
        self.cves = cves

    def __repr__(self):
        return self.title

    def to_dict(self):
        obj_dict = {}
        for i, j in self._sa_instance_state.attrs.items():
            if i in self.__public__:
                obj_dict[i] = j.value
        return obj_dict


class OvalRule(db.Model):
    __tablename__ = "vul_oval_rule"
    id = db.Column(db.Integer, primary_key=True, comment="主键")
    rule_name = db.Column(db.String(128), nullable=False, unique=True, comment="漏洞名称")
    alias_name = db.Column(db.String(128), nullable=True, default=None, comment="漏洞别名")
    type = db.Column(db.String(32), nullable=False, comment="漏洞类型")
    system_name = db.Column(db.String(64), nullable=False, comment="操作系统名称")
    repo_id = db.Column(db.Text, comment="对应漏洞库ID列表")
    operator_online = db.Column(db.String(32), nullable=True, default=None, comment="上线操作人")
    status = db.Column(db.Integer, nullable=False, comment="状态")
    rule_detail = db.Column(db.Text, nullable=True, comment="规则详情")
    gray_rule = db.Column(db.Text, nullable=True, comment="灰度规则")
    gmt_create = db.Column(db.DateTime, nullable=False, comment="创建时间")
    gmt_modified = db.Column(db.DateTime, nullable=False, comment="修改时间")
    gmt_online = db.Column(db.DateTime, nullable=True, default=None, comment="上线时间")
    comment = "oval规则"


class RuleUsnAid(db.Model):
    __tablename__ = "vul_rule_usn_aid"
    id = db.Column(db.Integer, primary_key=True, comment="主键")
    rule_name = db.Column(db.String(128), nullable=False, unique=True, comment="漏洞名称")
    alias_name = db.Column(db.String(128), nullable=True, default=None, comment="漏洞别名")
    cve_id = db.Column(db.Text, nullable=True, comment="CVE")
    aid = db.Column(db.String(128), nullable=True, comment="漏洞标识")
    type = db.Column(db.String(128), nullable=True, default=None, comment="漏洞版本")
    available = db.Column(db.SmallInteger, nullable=False, default=2, comment="可用性")
    comment = "漏洞规则关系"


class VulCVETitle(db.Model):
    # __tablename__ = "vul_new"
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True, comment="主键")
    avd_id = db.Column(db.String(128), nullable=False, comment="avd-id")
    gmt_create = db.Column(db.DateTime, nullable=False, default=datetime.now, comment="创建时间")
    gmt_modified = db.Column(db.DateTime, nullable=False, default=datetime.now, comment="修改时间")
    cwe_id = db.Column(db.String(50), nullable=True, default=None, comment="cwe-id")
    release_time = db.Column(db.DateTime, nullable=True, default=None, comment="发现/披露时间")
    cvss3_vector = db.Column(db.String(255), nullable=True, comment="cvss3打分串")
    product_type = db.Column(db.String(50), nullable=True, comment="产品类型\n（OS/Application/硬件）")
    vendor = db.Column(db.String(500), nullable=True, comment="漏洞厂商")
    product = db.Column(db.Text, nullable=True, comment="影响产品")
    cpe = db.Column(db.Text, nullable=True, comment="CPE")
    authentication = db.Column(db.String(5), nullable=True, comment="是否需要身份认证,\n1需要,0不需要")
    gained_privilege = db.Column(db.String(5), nullable=True, comment="是否能获取服务权限,\n1可以,0不可以")
    vul_level = db.Column(db.String(10), nullable=True, comment="漏洞等级严重、高危、中危、低危")
    summary_en = db.Column(db.Text, nullable=True, comment="漏洞简介-en")
    summary_cn = db.Column(db.Text, nullable=True, comment="漏洞简介-cn")
    poc = db.Column(db.Text, nullable=True, comment="poc利用脚本")
    poc_disclosure_time = db.Column(db.DateTime, nullable=True, comment="poc公开日期")
    solution_en = db.Column(db.Text, nullable=True, comment="修复方案-en")
    solution_cn = db.Column(db.Text, nullable=True, comment="修复方案-cn")
    reference = db.Column(db.Text, nullable=True, comment="参考链接")
    classify = db.Column(db.String(512), nullable=True, comment="漏洞类型分类")
    cve_id = db.Column(db.String(50), nullable=False, comment="cveid")
    cvss3_score = db.Column(db.String(50), nullable=False, comment="cvss3评分")
    title_cn = db.Column(db.String(50), nullable=False, comment="中文标题")
    title_en = db.Column(db.String(50), nullable=False, comment="英文标题")
    rule_status = db.Column(db.Integer, default=1, nullable=False, comment="状态")  # 1=未上线 2=灰度中 3=已上线
    is_translated = db.Column(db.Boolean, default=False, comment="人工审核")

    # gmt_modified = db.Column(db.DateTime, default=datetime.now, nullable=False, comment="更新时间")
    # comment = "漏洞信息"
    # __mapper_args__ = {
    #     "order_by": gmt_modified.desc()
    # }

    def __repr__(self):
        return self.cve_id


class VulNew(VulCVETitle):
    """线上表"""
    __tablename__ = "vul_new"
    comment = "漏洞信息"


class VulNewPre(VulCVETitle):
    """预发表"""
    __tablename__ = "vul_new_pre"
    comment = "漏洞信息(预发)"

    @classmethod
    def get_vul_from_last_month(cls):
        today = datetime.today()
        last_month = (today - timedelta(days=(today.day + 1))).month
        new_vuls = cls.query.filter(
            cls.gmt_create >= today.replace(month=last_month, day=1)
        ).all()
        return new_vuls

    def convert_references(self):
        import random
        from urllib.parse import urlparse, urljoin
        suffixes = ["security", "bulletins", "about/security", "security-center/advisory", "news", "security/advisory"]
        if self.reference:
            references = self.reference.split(",")
            refs = references.copy()
            for index, ref in enumerate(references):
                path = urlparse(ref).path
                if not path:
                    suffix = random.choice(suffixes)
                    if ref:
                        refs[index] = urljoin(ref, suffix)
                        print(ref, refs[index])
            return ",".join(refs)

    def excel_fields(self):
        from app.api.constants import CONVERT_INTO_CHINESE
        return [
            self.title_cn, self.summary_cn, self.cve_id, "",
            CONVERT_INTO_CHINESE.get("product_type").get(self.product_type)
            or CONVERT_INTO_CHINESE.get("product_type").get("default"),
            self.find_vendor(), self.find_product(), self.get_cpes(),
            self.release_time.strftime("%Y/%m/%d") if self.release_time else "",
            self.solution_cn, self.convert_references(), "", "", ""
        ]

    def find_vendor(self):
        if not self.vendor:
            vendor = db.session.execute(
                "select vendor from cpes WHERE nvd_json_id in (SELECT id from nvd_jsons WHERE cve_id=:cve_id)",
                {"cve_id": self.cve_id}
            ).fetchone()
            return vendor[0] if vendor else ""
        return self.vendor

    def find_product(self):
        if not self.product:
            product = db.session.execute(
                "select product from cpes WHERE nvd_json_id in (SELECT id from nvd_jsons WHERE cve_id=:cve_id)",
                {"cve_id": self.cve_id}
            ).fetchone()
            return product[0] if product else ""
        return self.vendor

    def get_cpes(self):
        from app.api.constants import cpe_sql_start, cpe_sql_end
        version = []
        start = db.session.execute(cpe_sql_start, {"cve_id": self.cve_id}).fetchone()
        end = db.session.execute(cpe_sql_end, {"cve_id": self.cve_id}).fetchone()
        if start:
            version.append(f">{start[0]}")
        if end:
            version.append(f"<{end[0]}")
        return ";".join(version) or "无"

    def get_cvss_detail(self):
        from app.api.tool import convert_cvss_to_values
        return convert_cvss_to_values(self.cvss3_vector)

    def export_excel_values(self):
        base_values = self.excel_fields()
        base_values.extend(self.get_cvss_detail())
        return base_values


class VulNewRun(VulCVETitle):
    """已上线"""
    __tablename__ = "vul_new_running"
    comment = "已上线漏洞"


class VulNewTest(VulCVETitle):
    """测试表"""
    __tablename__ = "vul_new_test"
    comment = "漏洞信息(test)"


class VulForPr(db.Model):
    """应急海报表"""
    __tablename__ = "vul_for_pr"
    id = db.Column(db.Integer, primary_key=True, comment="id")
    gmt_create = db.Column(db.DateTime, nullable=False, default=datetime.now, comment="创建时间")
    release_time = db.Column(db.DateTime, nullable=True, default=None, comment="发现/披露时间")
    title = db.Column(db.String(50), nullable=False, comment="漏洞标题")
    introduction = db.Column(db.Text, nullable=True, comment="简介")
    summary = db.Column(db.Text, nullable=True, comment="漏洞详情")
    QR_code = db.Column(db.String(512), comment="二维码")
    comment = "应急海报"

    def __repr__(self):
        return self.title or self.cve_id or self.id


class DataBase(ConfigBase):
    __tablename__ = "vul_config"
    comment = "数据库配置"


class KBModel(db.Model):
    __tablename__ = "vul_kb"
    id = db.Column(db.Integer, primary_key=True, comment="id")
    kb = db.Column(db.String(16), index=True, comment="KB")
    product = db.Column(db.String(), nullable=True, comment="影响产品")
    title = db.Column(db.String(128), nullable=True, comment="KB 标题")
    release_time = db.Column(db.Date, nullable=True, comment="时间")
    size = db.Column(db.String(16), nullable=True, comment="文件大小")
    description = db.Column(db.Text, nullable=True, comment="描述")
    severity = db.Column(db.String(24), nullable=True, comment="微软等级")
    reference = db.Column(db.String(512), nullable=True, comment="参考链接")
    replaced_by = db.Column(db.Text, nullable=True, comment="replaced by")
    replace = db.Column(db.Text, nullable=True, comment="replace")
    files = db.Column(db.Text, nullable=True, comment="文件名")
    architecture = db.Column(db.String(), comment="架构")
    download_from = db.Column(db.Text, nullable=True, comment="下载链接")
    update_id = db.Column(db.Text, nullable=True, comment="update id")
    monthly_rollup = db.Column(db.Boolean, default=False, comment="月度KB")
    security_kb = db.Column(db.String(), nullable=True, comment="安全KB")
    all_security_kb = db.Column(db.String(), nullable=True, comment="子安全KB")
    is_top = db.Column(db.Boolean, default=False, comment="顶级KB")
    comment = "KB列表"

    def __repr__(self):
        return self.title

    @property
    def top_status(self):
        return KBModel.query.filter(
            KBModel.replace.contains(self.kb),
            KBModel.architecture == self.architecture,
            KBModel.product == self.product).count() == 0

    @classmethod
    def fresh(cls):
        for query in cls.query.all():
            status = query.top_status
            if query.is_top != status:
                query.is_top = status
        db.session.commit()

    # @property
    # def is_top(self):
    #     return KBModel.query.filter(
    #         KBModel.replace.contains(self.kb),
    #         KBModel.architecture == self.architecture,
    #         KBModel.product == self.product
    #     ).count() == 0

# class SyncConfig(db.Model):
#     source = db.Column(db.Integer, db.ForeignKey("database.id"), comment="来源")
#     target = db.Column(db.Integer, db.ForeignKey("database.id"), comment="同步到")
#
#     def __init__(self, source, target):
#         self.source = source
#         self.target = target
