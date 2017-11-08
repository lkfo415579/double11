#!/usr/bin/env python 
# -*- coding: utf8 -*- 
'''
   @Brief : Translates server...
   @Modify : 2017/11/08 Edited By Revo, Marian Version, tornado server
   @Version : 7.3, N-best
   @CopyRight : newtranx
'''
import os
import sys
import time
import json
import uuid
import logging
import argparse
import validictory
import socket

from configobj import ConfigObj

import rd_util.apply_bpe as apply_bpe
import multiprocessing
import tornado.httpserver

from threading import Lock
from threading import Thread

from multiprocessing import Queue,Process

import tornado.ioloop
import tornado.web
import tornado.gen

import rd_util.translate as rd

#from langdetect import detect,DetectorFactory,detect_langs
from polyglot.detect import Detector
#import pycld2 as cld2

#DetectorFactory.seed = 0

parser = argparse.ArgumentParser()
parser.add_argument('--config', type=str, required=True , help="nmtserver config file")
parser.add_argument('--port'  , type=str, required=False, help="nmtserver listener port")

#-- parser args from input --#
args = parser.parse_args()

g_config_obj         = ConfigObj( args.config, encoding='UTF8')
g_config_obj['PORT'] = args.port if args.port is not None else g_config_obj['PORT']
source_lang = g_config_obj['SRC_LANG'][1:]
target_lang = g_config_obj['TGT_LANG'][1:]


import marian_python.libamunmt as nmt

#-------------------------------------------------------------------------------
#-- task --#
#-------------------------------------------------------------------------------
def build_task( params):
    task  = params
    nbest = task.get("nbest", None)
    if nbest is None:
        task["nbest"] = 1
    else :
        if int != type( task["nbest"]) :
            try :
                t = int ( task["nbest"])
                task["nbest"] = t
            except :
                task["nbest"] = 1

    detoken = task.get("detoken", None)
    if detoken is None:
        task["detoken"] = False
    else :
        if bool != type( task["detoken"]) :
            t = task["detoken"].strip().lower()
            if ( "true" == t) :
                task["detoken"] = True
            else :
                task["detoken"] = False
    
    text = task.get("text",None)
    
    if text.strip() == "":
        task["text"] = None
    return task
#--> end->Func: build_task




#-------------------------------------------------------------------------------
#--@brief: NMT server class...
#--
#--@param: logfile, ...
#-------------------------------------------------------------------------------
import concurrent.futures
from tornado.concurrent import run_on_executor
class Server( tornado.web.RequestHandler):
    executor = concurrent.futures.ThreadPoolExecutor( int( g_config_obj['N_TASKS']))

    def initialize( self, server_ctx):
        self.logger      = server_ctx['logger']
        self.bpe         = server_ctx['bpe']
        self.pidfile     = server_ctx['pidfile']
        self.NMT_PROCESS = server_ctx['NMT_PROCESS']
        self.SPLIT_SENTENCES_LEN = server_ctx['SPLIT_SENTENCES_LEN']
        self.task_id = tornado.process.task_id()
        self.rd_translator = rd.Translator( self.SPLIT_SENTENCES_LEN,source_lang, target_lang)
        self.timeout = server_ctx['timeout']
        self.detect_lang = server_ctx['detect_lang']
        self.alignment = server_ctx['alignment']
        self.N_BEST = server_ctx['N_BEST']
        self.DEBUG = server_ctx['DEBUG']
        self.BEAM_SIZE = int(server_ctx['BEAM_SIZE'])
        pass
    #-- end->Func: Server: __init__ --#

    
    @run_on_executor
    def sk_translate( self, task) :
        #assert n_best > N_BEST or not
        if task['nbest'] > self.BEAM_SIZE:
            return json.dumps("your requested nbest parameter is larger than the server's supported n_best size, the server's n_best size : %d" % self.BEAM_SIZE)
        elif task['nbest'] <= 0:
            return json.dumps("Your requested nbest parameter can't be less than 1")
        else:
            self.logger.info("Request Beam size:%d" % task['nbest'])
    
        self.rd_translator.pre_process( task)
        translations_dict = task
        translations_dict['translations'] = []
        result_saver = []
        
        input = [ self.bpe.segment(tmp_text.strip()).encode('utf8') for tmp_text in task['tokenized_sentences'] ]
        input = [ele for ele in input if ele != '']
        task['tokenized_sentences'] = input
        #self.logger.info("INPUT:{0}".format(input))

        #detect languages of each sentence
        if (self.detect_lang):
            BAD_Gate = []
            for index,sentence in enumerate(task['original_sentences']):
                try:
                    languages_result = Detector(sentence,True).languages
                    detected = {}
                    for lang_result in languages_result:
                        detected[lang_result.code[:2]] = lang_result.confidence * float(lang_result.read_bytes)
                    detected = [max(detected, key=detected.get)]
                    #or source_lang not in detected
                    if target_lang in detected and source_lang not in detected:
                        self.logger.info( "Detected:%s:%s" % (str(detected),sentence) )
                        for lang in languages_result:
                            self.logger.info( lang )
                        self.logger.info( '---' )
                        #FUCK got target sentence!!!
                        BAD_Gate.append(index)
                except Exception, e:
                    print "Exception:",e
                    BAD_Gate.append(index)

        #input into queue of GPU decoder
        q[self.task_id % self.NMT_PROCESS].put(input)
        Q_result = q_re[self.task_id % self.NMT_PROCESS].get(True)
        #handle n-best
        if self.N_BEST:
            tmp_all = [x.split("\n") for x in Q_result]
            n_best_sentences = []
            scores = []
            line_id = []
            align = []
            #n_best = len(tmp_all[0])
            n_best = task['nbest']
            for muti_line_of_one in tmp_all:
                for index,single in enumerate(muti_line_of_one):
                    if index >= n_best:
                        break
                    single = single.split(" ||| ")
                    line_id.append(int(single[0]))
                    n_best_sentences.append(single[1])
                    scores.append(float(single[-1]))
                    #output alignment information
                    if self.alignment:
                        align.append(single[2])


        for index,tmp_text in enumerate(Q_result):
            src_text = task['original_sentences'][index]
            result = dict()
            if self.detect_lang:
                #replace ori back to result
                if index in BAD_Gate:
                    result['translation'] = src_text
                else:
                    result['translation'] = tmp_text
            else:
                result['translation'] = tmp_text
            
            if result is not None :
                retCode = 0
                #-- All translate is success... --#
                self.logger.info('All translations are OK ...')
                
                if self.DEBUG:
                    if self.N_BEST:
                        nbest = []
                        for x in xrange(n_best):
                            id = index*(n_best)+x
                            #print id
                            translated = n_best_sentences[id]
                            #-- BPE process --#
                            translated = translated.replace('@@ ','')
                            #-- Display translation result
                            self.logger.info("Sentence[%d]:%s" % (id,translated))
                            #
                            nbest.append({'hyp':translated,'totalScore':scores[id],'line_num':line_id[id]})
                            if self.alignment:
                                nbest[-1]['alignment'] = align[id]
                            #print "nbest",
                            #print nbest
                            
                        result_dict = { 
                                       'src_text':src_text, \
                                       'ret_code':retCode, \
                                       'nbest'   :nbest}
                    else:
                        self.logger.info( result['translation'])
                        result_dict = {
                                       'src_text':src_text, \
                                       'ret_code':retCode, \
                                       'nbest'   :[{'hyp':result['translation'],  'totalScore':666 }]}
                    translations_dict['translations'].append(result_dict)
                else:
                    result_saver.append(result['translation'])
                    if index+1 == len(Q_result):
                        #last one
                        result_dict = {
                                       'src_text':"".join(task['original_sentences']), \
                                       'ret_code':retCode, \
                                       'nbest'   :[{'hyp':" ".join(result_saver),  'totalScore':666 }]}
                        translations_dict['translations'].append(result_dict)
        #print "translations_dict['translations'] : ",
        #print translations_dict['translations']
        result_json = self.rd_translator.post_process( translations_dict)
        #print "####"
        #print "result_json: ",
        #print result_json
        #self.logger.info("DETOKEN:{0}".format(task["detoken"]))
        result_json = rd._backward_transform({ 'translationId': uuid.uuid4().hex, 'sentences': result_json}, task["detoken"] )

        #del result_json['translation'][1:]
        return json.dumps( result_json)
    #-- end->Func: translate --#


    #-- The inside function: Server:translate --#
    @tornado.gen.coroutine
    def post( self):
        #print self.request.headers["Content-Type"]
        task = None
        if "application/json" in self.request.headers["Content-Type"] :
            try :
                task = json.loads( self.request.body.encode('utf-8'))
                task = build_task( task)
            except :
                task = None
        elif "application/x-www-form-urlencoded" in self.request.headers["Content-Type"] :
            task = {
                'srcl': self.get_argument( 'srcl'),
                'tgtl': self.get_argument( 'tgtl'),
                'text': self.get_argument( 'text'),
                'detoken': self.get_argument( 'detoken',True),
                'nbest': self.get_argument( 'nbest',1)
            }
            task = build_task(task)
            
        try :
            task_schema = {
                "type": "object",
                "properties": {
                    "srcl": {"type": "string"},
                    "tgtl": {"type": "string"},
                    "text": {"type": "string"},
                    "nbest": {"type": "integer", "required": False},
                    "detoken": {"type": "boolean", "required": False},
                },
            }
            validictory.validate( task, task_schema)
        except :
            task = None
        
        if (task is not None) and ( task.has_key('srcl') and task.has_key('tgtl') and task.has_key('text')) :
            #-- Initiazation --#
            text = task['text']
            ###concurrent,use future.result()
            result = self.sk_translate(task).result(self.timeout)
            ###
            retCode = 0
            self.set_header("Content-Type", "application/jsoncharset=utf-8")
            self.write(result)
            self.finish()
        else :
            self.set_status( 400)
            self.write( "Invalid request data, please check it.")
            self.finish()
    #--end->Func: Server:translate --#



#--end->Class: Server --#



q = []
q_re = []
#-- Server: S2B function --#
def S2B(S):
    if (S == "true") or (S == "True"):
        return True
    else:
        return False

#--end->Func: Server:S2B --#
def run_NMT(config,name):
    nmt.init(" ".join(config))
    
    while True:
        sentences = q[name].get(True)
        print "Decoder:%d" % name
        q_re[name].put(nmt.translate_batch(sentences))

def set_up_GPU_devices(NMT_ctx):
    
    config = ['-c', NMT_ctx['MARIAN_SETTING'],'--mini-batch',NMT_ctx['MINI_BATCH'],'--maxi-batch','100','-b',NMT_ctx['BEAM_SIZE'],'-d','0','--return-alignment','--n-best']
    for x in range(NMT_ctx['NMT_PROCESS']):
        q.append(Queue())
        q_re.append(Queue())
    if NMT_ctx['NORMALIZE']:
        config.append('-n')
    if not NMT_ctx['SUPPRESS_UNK']:
        config.append('-u')
    print "Total amount of queues : %d" % NMT_ctx['NMT_PROCESS']
    
    p_list = []
    for x in range(NMT_ctx['NMT_PROCESS']):
        config[9] = NMT_ctx['DEVICES_LIST'][x % len(NMT_ctx['DEVICES_LIST'])]
        print config
        pw = Process(target=run_NMT,args=(config,x,))
        pw.start()
        p_list.append(pw)
    
#-------------------------------------------------------------------------------
#--@biref: Server process instance...
#-------------------------------------------------------------------------------
def main():
    #-- set up logging --#
    logging.basicConfig( level    = logging.DEBUG, 
                         format   = "%(asctime)s[%(process)d] - %(name)s - %(message)s",
                         filename = g_config_obj[ 'LOG_FILE'] + '_' + g_config_obj[ 'PORT']+'.log' 
                       )
    logger      = logging.getLogger( 'NMTSERVER')
    SERVER_PROCESS = int( g_config_obj['SERVER_PROCESS'])
    ##
    BEAM_SIZE           = str( g_config_obj[ 'BEAM_SIZE'])
    NMT_PROCESS   = int( g_config_obj[ 'NMT_PROCESS'])
    SUPPRESS_UNK= S2B( g_config_obj['SUPPRESS_UNK'])
    DEVICES_LIST = g_config_obj['DEVICES_LIST'].split()
    DEVICES_LIST = [x.encode('utf8') for x in DEVICES_LIST]
    NORMALIZE = g_config_obj['NORMALIZE']
    MINI_BATCH = str(int(g_config_obj['MINI_BATCH']))
    MARIAN_SETTING = str(g_config_obj['MARIAN_SETTING'])
    ##
    bpe         = apply_bpe.BPE( g_config_obj[ 'CODE_BPE'])
    pidfile     = g_config_obj[ 'TRANSLATE_PID'] + '_' + g_config_obj[ 'PORT'] + '.pid'
    timeout     = int( g_config_obj[ 'TIMEOUT'])
    SPLIT_SENTENCES_LEN = int( g_config_obj[ 'SPLIT_SENTENCES_LEN'])
    detect_lang = S2B(str( g_config_obj['DETECT_LANG']))
    alignment =   S2B(str( g_config_obj['ALIGNMENT']))
    N_BEST = S2B( str(g_config_obj[ 'N_BEST']))
    DEBUG = S2B(str( g_config_obj['DEBUG']))
    ###Log
    logging.info("DEBUG MODEL : %s" % DEBUG)
    logging.info("DETECT Lang MODEL : %s" % detect_lang)
    ##
    assert NMT_PROCESS >= len(DEVICES_LIST),"N_PROCESS can't be less than amount of devices"
    logging.info("DEVICE_LIST:%s" % DEVICES_LIST)
    
    server_ctx = {
                  'logger'     : logger,
                  'bpe'        : bpe,
                  'pidfile'    : pidfile,
                  'NMT_PROCESS' : NMT_PROCESS,
                  'SPLIT_SENTENCES_LEN' : SPLIT_SENTENCES_LEN,
                  'timeout' : timeout,
                  'detect_lang' : detect_lang,
                  'DEBUG' : DEBUG,
                  'alignment' : alignment,
                  'N_BEST' : N_BEST,
                  'BEAM_SIZE' : BEAM_SIZE
    }
    NMT_ctx = {
                'N_BEST' : str(N_BEST),
                'BEAM_SIZE' : BEAM_SIZE,
                'NMT_PROCESS' : NMT_PROCESS,
                'SUPPRESS_UNK' : SUPPRESS_UNK,
                'DEVICES_LIST' : DEVICES_LIST,
                'NORMALIZE' : NORMALIZE,
                'MINI_BATCH' : MINI_BATCH,
                'MARIAN_SETTING' : MARIAN_SETTING
    }
    
    set_up_GPU_devices(NMT_ctx)
    
    app = tornado.web.Application([
        (r"/translate", Server, dict( server_ctx=server_ctx)),
    ])
    
    http_ctx = tornado.httpserver.HTTPServer( app)
    http_ctx.bind( int( g_config_obj['PORT']), '0.0.0.0', socket.AF_INET, int( g_config_obj['BACKLOG'])) 
    http_ctx.start(SERVER_PROCESS)
    tornado.ioloop.IOLoop.current().start()
#--end->Func: main --#

#-------------------------------------------------------------------------------
#-- The Server process main instance, do there and running...
#-------------------------------------------------------------------------------
if __name__ =="__main__":
    main()

