# -*- coding: utf-8 -*-
# !/usr/bin/env python
import uuid

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import codecs
import socket


from rd_util.tokenize import Tokenizer
from rd_util.detokenize import Detokenizer
from rd_util.sentence_spliter import split_function
#from rd_util.ph_number import Generizer

from regex import Regex, UNICODE

END_PUNCTUATION=['.','!','?'] 
DOUBLE_END_PUNCTUATION=[
        (',.',','),
        ('..','.'),
        ('!.','!'),
        ('?.','?')
           ] 

#CALL_SMT_THRESHOLD = 1

def _backward_transform(result, dodetok):
    """Transform the produced output structure to old format.
    Soon to be deprecated."""
    translation = []
    min_nbest_length = min([len(s['translated']) for s in result['sentences']])
    #print "\n"
    #print "min_nbest:%d" % min_nbest_length
    
    #print "###################\nresult"
    #print result
    
    for index,sent in enumerate(result['sentences']):
        #assign first one
        one_sentence = {}
        if dodetok:
            one_sentence['src-tokenized'] = sent['src-tokenized']
            #one_sentence['src-tokenized'] = "ABC"
        one_sentence['src_text'] = sent['translated'][0]['src_text']
        one_sentence['ret_code'] = sent['translated'][0]['ret_code']
        one_sentence['line_num'] = sent['translated'][0]['line_num']
        #
        translated = []
        for sent_data in sent['translated']:
            oldformat = {}
            #if dodetok:
            #    oldformat['src-tokenized'] = sent['src-tokenized']
            #print "sent_data"
            #print sent_data
            #print "=========="
            oldformat['text'] = sent_data['text']
            oldformat['rank'] = sent_data['rank']
            oldformat['score'] = sent_data['score']
            if sent_data["alignment"]:
                oldformat['alignment'] = sent_data["alignment"]
            translated.append(oldformat)
        if min_nbest_length == 1:
            one_sentence['text'] = sent['translated'][0]['text']
            one_sentence['rank'] = 0
            one_sentence['score'] = 666
        else:
            one_sentence['n_best'] = translated
        #print translated
        translation.append(one_sentence)
    
    '''for rank in range(0, min_nbest_length):
        translated = []
        for sent in result['sentences']:
            oldformat = {}
            if dodetok:
                oldformat['src-tokenized'] = sent['src-tokenized']

            oldformat['text'] = sent['translated'][rank]['text']

            #liangss add for support nmtserver
            oldformat['src_text'] = sent['translated'][rank]['src_text']
            oldformat['ret_code'] = sent['translated'][rank]['ret_code']

            oldformat['rank'] = rank
            oldformat['score'] = sent['translated'][rank]['score']

            translated.append(oldformat)

        translation.append({'translated': translated, 'translationId': result['translationId']})'''
    

    return {'translation': [{'translated':translation,'translationId': result['translationId']}]}


class Translator:

    def __init__(self, SPLIT_SENTENCES_LEN, source_lang, target_lang):
        self.source_lang = source_lang
        self.splitter = split_function(source_lang)
        # this is added on 11/21 2015
        if source_lang == 'zh' or source_lang== 'nzh' or source_lang=='ru' or source_lang=='nru':
            self.tokenizer = Tokenizer({'lowercase': False, 'moses_escape': True})
        else:
            self.tokenizer = Tokenizer({'lowercase': True, 'moses_escape': True})
        
        #self.detokenizer_src = Detokenizer({'moses_deescape': True, 'capitalize_sents': True, 'language': source_lang})
        self.detokenizer = Detokenizer({'moses_deescape': True, 'capitalize_sents': True, 'language': target_lang})
        
        q2b = codecs.open('rd_util/q2b','r','utf8').readlines();
        self.q2b = []
        self.q2b_dict = {}
        for line in q2b:
            temp = line.strip('\n').split('/')
            self.q2b.append([temp[0],temp[1]])
            self.q2b_dict[temp[0]] = temp[1]
        
        self.split_sentence_len = SPLIT_SENTENCES_LEN
        
        #self.generizer = Generizer()

    def pre_process(self, task):
        #text = task["text"].decode('utf-8')
        text = task["text"]
        task["original_sentences"] = []
        copy_text = text[:]
        #parse q2b
        #if task['srcl'] == 'zh' or task['srcl'] == 'nzh' or \
        #        task['srcl']=='ja' or task['srcl']=='nja' \
        #        or task['srcl'] == 'nru':
        #copy_text = copy_text.replace(" ","")
        #for ele in self.q2b:
        #    text = text.replace(ele[0],ele[1])
        #import re
        #text = 'Allowed Hello Hollow'
        #for m in re.finditer('ll', text):
        #    print('ll found', m.start() - m.end())
        for i,j in self.q2b_dict.iteritems():
            text = text.replace(i,j)
            #for m in re.finditer(i, text):
            #    tmp = m.end() - 1
            #    print(i+' found', tmp)
            #    text[tmp] = j
                
        sentences = self.splitter(text, max_len=self.split_sentence_len)
        #searching backward to find the last letter
        for x in sentences[:-1]:
            cut_pos = len(x)
            
            #print "cut_pos_",cut_pos
            last_word = x[-4:-2]
            #print "last_word3_",last_word,"*END"
            real_pos = copy_text[:cut_pos].rfind(last_word)
            #handle CJK
            current_pos = -4
            runner = 0
            while(real_pos == -1):
                #can't find,fucked CJK
                last_word = x[current_pos]
                current_pos-=1
                #runner += 1
                if last_word == " ":
                    continue
                
                #print "%last_word3_",last_word,
                #print "*END"
                real_pos = copy_text[:cut_pos].rfind(last_word)
                #print "@real_pos,",real_pos
                if real_pos == -1:
                    #again!
                    runner +=1
            #else:
            #    real_pos+=runner
            real_pos += 3+runner
            #print "real_pos,",real_pos
            #print "--"
            task["original_sentences"].append(copy_text[:real_pos])
            copy_text = copy_text[real_pos:]
        task["original_sentences"].append(copy_text)
        
        #splitter_num = []
        #for x in sentences:
        #    splitter_num.append(len(x.replace(" ","")))
        '''for x in sentences:
            if len(x) < 3:
                continue
            last_3word = str(x[-4])
            #end_word = x[-1]
            end_pos = copy_text.find(last_3word)
            task["original_sentences"].append(copy_text[:end_pos+3])
            copy_text = copy_text[end_pos+3:]
            #splitter_num.append(end_pos+3)'''
        '''    if task['srcl'] == 'zh' or task['srcl'] == 'nzh' or \
                    task['srcl']=='ja' or task['srcl']=='nja' \
                    or task['srcl'] == 'nru':
                splitter_num.append(len(x.replace(" ","")))
            else:
                #print "---"
                #print x
                #print len(x)
                splitter_num.append(len(x))
        '''
        
        #reverse q2b
        
        
        #for num in splitter_num:
        #    task["original_sentences"].append(copy_text[:num])
        #    copy_text = copy_text[num:]
        #for x in sentences:
        #    for ele in self.b2q:
        #        task["original_sentences"].append(x.replace(ele[0],ele[1]))
        #task["original_sentences"]  =  [x for x in sentences]
        #task["original_sentences"]  =  [self.detokenizer_src.detokenize(x) for x in sentences]
        #task["tokenized_sentences"] = [self.generizer.tokenize(self.tokenizer.tokenize(sentence, self.source_lang)) for sentence in sentences]
        task["tokenized_sentences"] = [self.tokenizer.tokenize(sentence, self.source_lang) for sentence in sentences]
        #print task["tokenized_sentences"]

    def post_process(self, task):

        translations = task["translations"]
        results = []
        for index, translation in enumerate(translations):
            hypos = []
            for rank, option in enumerate(translation["nbest"]):
                hyp = option["hyp"]
                score = option["totalScore"]
                line_num = option["line_num"]
                hypo = {
                    "rank": rank,
                    "score": score,
                    "text": self.detokenizer.detokenize(hyp) if task["detoken"] else hyp,
                    "src_text": translation["src_text"] if translation.has_key("src_text") else None,
                    "ret_code": translation["ret_code"] if translation.has_key("ret_code") else 0,
                    "alignment" : option["alignment"] if option.has_key("alignment") else None,
                    "line_num" : line_num,
                }
                for char, repl in DOUBLE_END_PUNCTUATION: 
                    hypo['text'] = hypo['text'].replace(char, repl)
                    
                hypos.append(hypo)
            result = {
                'src': task["original_sentences"][index],
                'translated': hypos,
            }

            if task["detoken"]:
                result['src-tokenized'] = task["tokenized_sentences"][index]

            results.append(result)
        return results

