import pickle
from xml import sax
from xml.dom import minidom

from flask import request


def selected_document(flag):
    parser = sax.make_parser()
    parser.setFeature(sax.handler.feature_external_ges, True)
    submitted = request.data
    documents = ["<ledger/>", submitted]
    document = documents[0] if flag else "<receipt/>"
    return minidom.parseString(document, parser)


def submitted_document(flag):
    parser = sax.make_parser()
    parser.setFeature(sax.handler.feature_external_ges, True)
    submitted = request.data
    documents = ["<ledger/>", submitted]
    document = documents[1] if flag else "<receipt/>"
    return minidom.parseString(document, parser)


def file_document():
    parser = sax.make_parser()
    parser.setFeature(sax.handler.feature_external_ges, True)
    return minidom.parse("ledger.xml", parser)


def fixed_record():
    return pickle.loads(b"K\x07?")


def submitted_record():
    record = request.data
    return pickle.loads(record)
