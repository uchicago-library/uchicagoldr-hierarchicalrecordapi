from flask import jsonify, Blueprint, current_app as app
from flask_restful import Resource, Api, reqparse
from uuid import uuid1
from os import scandir
from os import remove
from os.path import join
from werkzeug.utils import secure_filename
from re import compile as regex_compile

from uchicagoldrapicore.configuration import DATA
from uchicagoldrapicore.responses.apiresponse import APIResponse
from uchicagoldrapicore.lib.apiexceptionhandler import APIExceptionHandler

from hierarchicalrecord.hierarchicalrecord import HierarchicalRecord
from hierarchicalrecord.recordconf import RecordConf
from hierarchicalrecord.recordvalidator import RecordValidator


# Globals
_ALPHANUM_PATTERN = regex_compile("^[a-zA-Z0-9]+$")
_NUMERIC_PATTERN = regex_compile("^[0-9]+$")
_EXCEPTION_HANDLER = APIExceptionHandler()

_STORAGE_ROOT = DATA["STORAGE_ROOT"]


# Most of these are abstracted because they should be hooked
# to some kind of database model in the future
#
# TODO
# Probably make these base functions delegators to
# implementation specific functions

def only_alphanumeric(x):
    if _ALPHANUM_PATTERN.match(x):
        return True
    return False


def retrieve_record(identifier):
    identifier = secure_filename(identifier)
    if not only_alphanumeric(identifier):
        raise ValueError("Record identifiers must be alphanumeric.")
    r = HierarchicalRecord(
        from_file=join(
            _STORAGE_ROOT, 'records', identifier
        )
    )
    return r


def write_record(record, identifier):
    identifier = secure_filename(identifier)
    if not only_alphanumeric(identifier):
        raise ValueError("Record identifiers must be alphanumeric.")
    with open(
        join(_STORAGE_ROOT, 'records', identifier), 'w'
    ) as f:
        f.write(record.toJSON())


def delete_record(identifier):
    identifier = secure_filename(identifier)
    if not only_alphanumeric(identifier):
        raise ValueError("Record identifiers must be alphanumeric.")
    rec_path = join(_STORAGE_ROOT, 'records', identifier)
    remove(rec_path)


def retrieve_conf(conf_str):
    conf_str = secure_filename(conf_str)
    c = RecordConf()
    if not only_alphanumeric(conf_str):
        raise ValueError("Conf identifiers must be alphanumeric.")
    c.from_csv(
        join(_STORAGE_ROOT, 'confs', conf_str+".csv")
    )
    return c


def write_conf(conf, conf_id):
    conf_id = secure_filename(conf_id)
    if not only_alphanumeric(conf_id):
        raise ValueError("Conf identifiers must be alphanumeric.")
    path = join(_STORAGE_ROOT, 'confs', conf_id+".csv")
    conf.to_csv(path)


def delete_conf(identifier):
    identifier = secure_filename(identifier)
    if not only_alphanumeric(identifier):
        raise ValueError("Conf identifiers must be alphanumeric.")
    rec_path = join(_STORAGE_ROOT, 'confs', identifier+".csv")
    remove(rec_path)


def retrieve_category(category):
    category = secure_filename(category)
    if not only_alphanumeric(category):
        raise ValueError("Category identifiers must be alphanumeric.")
    c = RecordCategory(category)
    p = join(_STORAGE_ROOT, 'org', category)
    try:
        with open(p, 'r') as f:
            for line in f.readlines():
                c.add_record(line.rstrip('\n'))
    except OSError:
        pass
    return c


def write_category(c, identifier):
    identifier = secure_filename(identifier)
    if not only_alphanumeric(identifier):
        raise ValueError("Categories must be alphanumeric.")
    path = join(_STORAGE_ROOT, 'org', identifier)
    recs = set(c.records)
    with open(path, 'w') as f:
        for x in recs:
            f.write(x+'\n')


def delete_category(identifier):
    identifier = secure_filename(identifier)
    if not only_alphanumeric(identifier):
        raise ValueError("Categories must be alphanumeric.")
    rec_path = join(_STORAGE_ROOT, 'org', identifier)
    remove(rec_path)


def build_validator(conf):
    return RecordValidator(conf)


def retrieve_validator(conf_id):
    c = retrieve_conf(conf_id)
    return build_validator(c)


def get_categories():
    r = []
    for x in scandir(join(_STORAGE_ROOT, 'org')):
        if not x.is_file():
            continue
        c = retrieve_category(x.name)
        r.append(c)
    return r


def get_existing_record_identifiers():
    return (x.name for x in scandir(
        join(
            _STORAGE_ROOT, 'records'
        )) if x.is_file())


def get_existing_conf_identifiers():
    return (x.name for x in scandir(
        join(
            _STORAGE_ROOT, 'confs'
        )) if x.is_file())


def get_existing_categories():
    return (x.name for x in scandir(
        join(
            _STORAGE_ROOT, 'org'
        )) if x.is_file())


def parse_value(value):
    if value is "True":
        return True
    elif value is "False":
        return False
    elif value is "{}":
        return {}
    elif value is "[]":
        return []
    elif _NUMERIC_PATTERN.match(value):
        return int(value)
    else:
        return value


class RecordCategory(object):
    def __init__(self, title):
        self._title = None
        self._records = []
        self.title = title

    def get_title(self):
        return self._title

    def set_title(self, title):
        if not only_alphanumeric(title):
            raise ValueError("Category titles can only be alphanumeric")
        self._title = title

    def get_records(self):
        return self._records

    def set_records(self, record_ids):
        self._records = []
        for x in record_ids:
            self.add_record(x)

    def del_records(self):
        self._records = []

    def add_record(self, record_id):
        if record_id in get_existing_record_identifiers():
            self._records.append(record_id)
        else:
            raise ValueError(
                "That identifier ({}) doesn't exist.".format(record_id)
            )

    def remove_record(self, record_id, whiff_is_error=True):
        atleast_one = False
        for i, x in enumerate(self.records):
            if x == record_id:
                atleast_one = True
                del self.records[i]
        if not atleast_one and whiff_is_error:
            raise ValueError(
                "{} doesn't appear in the records list".format(record_id)
            )

    title = property(get_title, set_title)
    records = property(get_records, set_records, del_records)


class RecordsRoot(Resource):
    def get(self):
        # List all records
        try:
            r = APIResponse(
                "success",
                data={"record_identifiers": [x for x in
                                             get_existing_record_identifiers()]}
            )
            return jsonify(r.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def post(self):
        # New Record
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('record', type=dict)
            parser.add_argument('conf_identifier', type=str)
            args = parser.parse_args()
            identifier = uuid1().hex
            r = HierarchicalRecord()
            if args['record']:
                r.data = args['record']
            if args['conf_identifier']:
                validator = retrieve_validator(args['conf_identifier'])
                validity = validator.validate(r)
                if not validity[0]:
                    return jsonify(
                        APIResponse("fail", errors=validity[1]).dictify()
                    )
            write_record(r, identifier)
            resp = APIResponse("success",
                               data={"record_identifier": identifier,
                                     "record": r.data})
            return jsonify(resp.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


class RecordRoot(Resource):
    def get(self, identifier):
        # Get the whole record
        try:
            r = retrieve_record(identifier)
            resp = APIResponse("success",
                               data={"record": r.data,
                                     "record_identifier": identifier})
            return jsonify(resp.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def put(self, identifier):
        # overwrite a whole record
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('record', type=dict, required=True)
            parser.add_argument('conf_identifier', type=str)
            args = parser.parse_args()
            record = retrieve_record(identifier)
            record.data = args.record
            if args['conf_identifier']:
                validator = retrieve_validator(args['conf_identifier'])
                validity = validator.validate(record)
                if not validity[0]:
                    return jsonify(
                        APIResponse("fail", errors=validity[1]).dictify()
                    )
            write_record(record, identifier)
            return jsonify(
                APIResponse("success",
                            data={'record_identifier': identifier,
                                  'record': record.data}).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def delete(self, identifier):
        # delete a record
        try:
            delete_record(identifier)
            r = APIResponse(
                "success",
                data={"records": [x for x in get_existing_record_identifiers()],
                      "deleted_identifier": identifier}
            )
            return jsonify(r.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


class EntryRoot(Resource):
    def get(self, identifier, key):
        # get a value
        try:
            r = retrieve_record(identifier)
            v = r[key]
            return jsonify(
                APIResponse(
                    "success",
                    data={'record_identifier': identifier,
                          'key': key, 'value': v}
                ).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def post(self, identifier, key):
        # Set a value
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('value', required=True)
            parser.add_argument('conf_identifier', type=str)
            args = parser.parse_args()
            v = parse_value(args['value'])
            r = retrieve_record(identifier)
            r[key] = v
            if args['conf_identifier']:
                validator = retrieve_validator(args['conf_identifier'])
                validity = validator.validate(r)
                if not validity[0]:
                    return jsonify(
                        APIResponse("fail", errors=validity[1]).dictify()
                    )
            write_record(r, identifier)
            return jsonify(
                APIResponse("success",
                            data={'record': r.data,
                                  'record_identifier': identifier}).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def delete(self, identifier, key):
        # delete a value
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('conf_identifier', type=str)
            args = parser.parse_args()
            r = retrieve_record(identifier)
            del r[key]
            if args['conf_identifier']:
                validator = retrieve_validator(args['conf_identifier'])
                validity = validator.validate(r)
                if not validity[0]:
                    return jsonify(
                        APIResponse("fail", errors=validity[1]).dictify()
                    )
            write_record(r, identifier)
            return jsonify(
                APIResponse("success",
                            data={'record': r.data,
                                  'record_identifier': identifier}).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


class ValidationRoot(Resource):
    def post(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('record_identifier', type=str, required=True)
            parser.add_argument('conf_identifier', type=str, required=True)
            args = parser.parse_args(strict=True)

            v = retrieve_validator(args['conf_identifier'])
            r = retrieve_record(args['record_identifier'])
            validity = v.validate(r)
            resp = APIResponse("success",
                               data={
                                   "is_valid": validity[0],
                                   "validation_errors": validity[1],
                                   "record_identifier": args['record_identifier'],
                                   "conf_identifier": args['conf_identifier'],
                                   "record": r.data
                                   }
                               )
            return jsonify(resp.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


class ConfsRoot(Resource):
    def get(self):
        # list all confs
        try:
            r = APIResponse(
                "success",
                data={"conf_identifiers": [x for x in
                                           get_existing_conf_identifiers()]}
            )
            return jsonify(r.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def post(self):
        # New Conf
        try:
            new_conf_identifier = uuid1().hex
            c = RecordConf()
            write_conf(c, new_conf_identifier)
            r = APIResponse(
                "success",
                data={"conf_identifier": new_conf_identifier,
                      "conf": c.data}
            )
            return jsonify(r.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


class ConfRoot(Resource):
    def get(self, identifier):
        # return a specific conf
        try:
            c = retrieve_conf(identifier)
            return jsonify(
                APIResponse("success",
                            data={"conf_identifier": identifier,
                                  "conf": c.data}
                            ).dictify()
            )

        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def post(self, identifier):
        # set validation rule
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('rule', type=dict, required=True)
            args = parser.parse_args()
            c = retrieve_conf(identifier)
            c.add_rule(args['rule'])
            write_conf(c, identifier)
            return jsonify(
                APIResponse("success",
                            data={"conf_identifier": identifier,
                                  "conf": c.data}
                            ).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def delete(self, identifier):
        # Delete this conf
        try:
            delete_conf(identifier)
            r = APIResponse(
                "success",
                data={"conf_identifiers": [x for x in
                                           get_existing_conf_identifiers()],
                      "deleted_conf_identifier": identifier}
            )
            return jsonify(r.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


class RulesRoot(Resource):
    def get(self, identifier, rule_id):
        # get a rule
        try:
            c = retrieve_conf(identifier)
            found_one = False
            for x in c.data:
                if x['id'] == rule_id:
                    rule = x
                    found_one = True
            if not found_one:
                raise ValueError(
                    "No rule with id {} in conf {}".format(rule_id, identifier)
                )
            r = APIResponse(
                "success",
                data={"conf_identifier": identifier,
                      "rule": rule}
            )
            return jsonify(r.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def delete(self, identifier, rule_id):
        # delete a rule
        try:
            c = retrieve_conf(identifier)
            c.data = [x for x in c.data if x['id'] != rule_id]
            write_conf(c, identifier)
            return jsonify(
                APIResponse("success", data={"conf_identifier": identifier,
                                             "conf": c.data}).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


class RuleComponentRoot(Resource):
    def get(self, identifier, rule_id, component):
        # get a rule component
        try:
            c = retrieve_conf(identifier)
            rule = None
            for x in c.data:
                if x['id'] == rule_id:
                    rule = x
            if rule is None:
                raise ValueError(
                    "No rule with id {} in conf {}".format(rule_id, identifier)
                )
            try:
                value = x[component]
            except KeyError:
                raise ValueError(
                    "No component named {} in rule {} in conf {}".format(component,
                                                                         rule_id,
                                                                         identifier)
                )
            return jsonify(
                APIResponse("success", data={"conf_identifier": identifier,
                                             "rule_id": rule_id,
                                             "component": component,
                                             "value": value}).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def delete(self, identifier, rule_id, component):
        # remove a rule component
        try:
            c = retrieve_conf(identifier)
            rule = None
            for x in c.data:
                if x['id'] == rule_id:
                    rule = x
            if rule is None:
                raise ValueError(
                    "No rule with id {} in conf {}".format(rule_id, identifier)
                )
            try:
                x[component] = ""
                value = x[component]
            except KeyError:
                raise ValueError(
                    "No component named {} in rule {} in conf {}".format(component,
                                                                         rule_id,
                                                                         identifier)
                )
            write_conf(c, identifier)
            return jsonify(
                APIResponse("success", data={"conf_identifier": identifier,
                                             "rule_id": rule_id,
                                             "component": component,
                                             "value": value}).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())
        pass

    def post(self, identifier, rule_id, component):
        # Add a rule component to this rule
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('component_value', type=str, required=True)
            args = parser.parse_args()

            c = retrieve_conf(identifier)
            rule = None
            for x in c.data:
                if x['id'] == rule_id:
                    rule = x
            if rule is None:
                raise ValueError(
                    "No rule with id {} in conf {}".format(rule_id, identifier)
                )
            try:
                x[component] = args['component_value']
                value = x[component]
            except KeyError:
                raise ValueError(
                    "No component named {} in rule {} in conf {}".format(component,
                                                                         rule_id,
                                                                         identifier)
                )
            write_conf(c, identifier)
            return jsonify(
                APIResponse("success", data={"conf_identifier": identifier,
                                             "rule_id": rule_id,
                                             "component": component,
                                             "value": value}).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


class CategoriesRoot(Resource):
    def get(self):
        # list all categories
        try:
            r = APIResponse(
                "success",
                data={"category_identifiers": [x for x in
                                               get_existing_categories()]}
            )
            return jsonify(r.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def post(self):
        # Add a category
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('category_identifier', type=str, required=True)
            args = parser.parse_args()

            if not only_alphanumeric(args['category_identifier']):
                raise ValueError(
                    "Category identifiers can only be alphanumeric."
                )

            # This line shouldn't do anything, but why not be paranoid about it
            args['category_identifier'] = secure_filename(
                args['category_identifier']
            )

            if args['category_identifier'] in get_existing_categories():
                raise ValueError("That cat id already exists, " +
                                 "please specify a different identifier.")

            c = retrieve_category(args['category_identifier'])
            write_category(c, args['category_identifier'])
            return jsonify(
                APIResponse(
                    "success",
                    data={"category_identifier": args['category_identifier'],
                          "record_identifiers": c.records}
                ).dictify()
            )

        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


class CategoryRoot(Resource):
    def get(self, cat_identifier):
        # list all records in this category
        try:
            c = retrieve_category(cat_identifier)
            return jsonify(
                APIResponse("success",
                            data={"category_identifier": cat_identifier,
                                  "record_identifiers": c.records}).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def post(self, cat_identifier):
        # Add a record to this category
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('record_identifier', type=str, required=True)
            args = parser.parse_args()

            c = retrieve_category(cat_identifier)
            c.add_record(args['record_identifier'])
            write_category(c, cat_identifier)
            return jsonify(
                APIResponse("success",
                            data={"category_identifier": cat_identifier,
                                  "record_identifiers": c.records}).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def delete(self, cat_identifier):
        # delete this category
        try:
            delete_category(cat_identifier)
            r = APIResponse(
                "success",
                data={"category_identifiers": [x for x in
                                               get_existing_categories()]}
            )
            return jsonify(r.dictify())
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


class CategoryMember(Resource):
    def get(self, cat_identifier, rec_identifier):
        # Query the category to see if an identifier is in it
        try:
            c = retrieve_category(cat_identifier)
            if rec_identifier in c.records:
                return jsonify(
                    APIResponse("success",
                                data={"category_identifier": cat_identifier,
                                      "record_identifiers": c.records,
                                      "record_present": True}).dictify()
                )
            else:
                raise ValueError(
                    "Record Identifier: {} not present in Category: {}".format(rec_identifier,
                                                                               cat_identifier)
                )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())

    def delete(self, cat_identifier, rec_identifier):
        # remove this member from the category
        try:
            c = retrieve_category(cat_identifier)
            c.records = [x for x in c.records if x != rec_identifier]
            write_category(c, cat_identifier)
            return jsonify(
                APIResponse("success",
                            data={"category_identifier": cat_identifier,
                                  "record_identifiers": c.records}).dictify()
            )
        except Exception as e:
            return jsonify(_EXCEPTION_HANDLER.handle(e).dictify())


# Create our app, hook the API to it, and add our resources
BP = Blueprint("hierarchicalrecordsapi", __name__)

api = Api(BP)

# Record manipulation endpoints
api.add_resource(RecordsRoot, '/record')
api.add_resource(RecordRoot, '/record/<string:identifier>')
api.add_resource(EntryRoot, '/record/<string:identifier>/<string:key>')

# Validation endpoint
api.add_resource(ValidationRoot, '/validate')

# Conf manipulation endpoints
api.add_resource(ConfsRoot, '/conf')
api.add_resource(ConfRoot, '/conf/<string:identifier>')
api.add_resource(RulesRoot, '/conf/<string:identifier>/<string:rule_id>')
api.add_resource(RuleComponentRoot, '/conf/<string:identifier>/<string:rule_id>/<string:component>')

# Organization manipulation endpoints
api.add_resource(CategoriesRoot, '/category')
api.add_resource(CategoryRoot, '/category/<string:cat_identifier>')
api.add_resource(CategoryMember, '/category/<string:cat_identifier>/<string:rec_identifier>')
