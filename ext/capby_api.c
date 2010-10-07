/*
 * This file is part of Capby.
 * 
 * Capby is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Capby is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Capby.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Copyright (c) 2009, Di Cioccio Lucas
 */

#include <ruby.h>
#include <time.h>
#include <pcap.h>
#include <errno.h>

#ifdef HAVE_RUBYSIG_H
#include <rubysig.h>

#ifdef HAVE_TRAP_BEG_M
#ifndef HAVE_TRAP_END_M
#error TRAP_BEG macro here but not TRAP_END
#endif
#endif
#endif /* RUBYSIG_H */

#ifndef RUBY_19
#include <version.h>
#else
#include <ruby/intern.h>
#endif /* RUBY_19 */

#ifndef WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifndef CAPBY_SOURCE
#define CAPBY_SOURCE
#endif

#ifndef CAPBY_HEADERS
#include "capby.h"
#endif

#ifdef HAVE_DNET_H
#include <dnet.h>
#endif

/* local function prototypes */

static void __capby_init_CST( void );
static void __capby_init_CST_DLT_mapping( void );
static void __capby_init_CST_DLT( void );
static void __capby_init_DEV( void );
static void __capby_init_CAP( void );
static void __capby_init_PKT( void );
static void __capby_check_binary( void );


static VALUE capby_CST_DLT_aref(VALUE, VALUE);
static VALUE capby_CST_DLT_all(VALUE);

static VALUE capby_CAP_new(VALUE, VALUE);
static VALUE capby_CAP_new_for_file(VALUE, VALUE);
static VALUE capby_CAP_get_dlt(VALUE);
static VALUE capby_CAP_get_stats(VALUE);
static VALUE capby_CAP_get_blocking(VALUE);
static VALUE capby_CAP_set_blocking(VALUE, VALUE);
static VALUE capby_CAP_get_direction(VALUE);
static VALUE capby_CAP_set_direction(VALUE, VALUE);
static VALUE capby_CAP_set_bufsize(VALUE, VALUE);
static VALUE capby_CAP_set_timeout(VALUE, VALUE);
static VALUE capby_CAP_set_snaplen(VALUE, VALUE);
static VALUE capby_CAP_each(int, VALUE *, VALUE);
static VALUE capby_CAP_get_filter(VALUE);
static VALUE capby_CAP_set_filter(int, VALUE *, VALUE);
static VALUE __capby_CAP_each(VALUE);
static VALUE __capby_CAP_each_ensure(VALUE);
static VALUE capby_CAP_next_packet(VALUE);
static void __capby_CAP_mark_capture(struct capby_capture *);
static void __capby_CAP_free_capture(struct capby_capture *);
static VALUE capby_CAP_send_pkts(VALUE, VALUE);
static VALUE capby_CAP_send_pkts_no_typecheck(VALUE, VALUE);
static VALUE capby_CAP_send_pkt(VALUE, VALUE);
static VALUE capby_CAP_send_pkt_no_typecheck(VALUE, VALUE);

static VALUE capby_PKT_send_no_typecheck(VALUE, VALUE);
static VALUE capby_PKT_send(VALUE, VALUE);
static VALUE capby_PKT_new(VALUE, VALUE);
static VALUE __capby_PKT_from_pcap_data(const struct pcap_pkthdr *, const u_char *);
static void __capby_PKT_mark_packet(struct capby_packet *);
static void __capby_PKT_free_packet(struct capby_packet *);

static VALUE capby_DEV_all(VALUE);
static VALUE capby_DEV_get_name(VALUE);
static VALUE capby_DEV_get_desc(VALUE);
static VALUE capby_DEV_is_loopback(VALUE);
static VALUE capby_DEV_get_addresses(VALUE);
static void __capby_DEV_mark_dev(pcap_if_t*);
static void __capby_DEV_free_dev(pcap_if_t*);
#ifdef HAVE_DNET_H
static VALUE capby_DEV_get_hw_address(VALUE);
#endif

/* function definitions */

void capby_warn_not_equal(VALUE val1, VALUE val2, const char * msg) 
{
#ifdef HAVE_RB_EQUAL
  if (msg != NULL) {
    if (rb_equal(val1, val2) == Qfalse)
      rb_warn("%s", msg);
  }
#else
  rb_warn("no test to say if we should warn: %s\n", msg);
#endif
}

int capby_SYM2DLT(VALUE sym) 
{
  struct capby_datalink_triolet * curr = NULL;
  Check_Type(sym, T_SYMBOL);

  for (curr=capby_datalink_mapping; curr->name != NULL; curr++) {
    if (rb_to_id(curr->sym) == rb_to_id(sym))
      break;
  }

  if (curr->name == NULL)
    return DLT_NULL;

  return curr->idx;
}

VALUE capby_DLT2SYM(int idx) 
{
  struct capby_datalink_triolet * curr = NULL;

  for (curr=capby_datalink_mapping; curr->name != NULL; curr++) {
    if (curr->idx == idx)
      break;
  }

  return curr->sym;
}


static VALUE capby_CST_DLT_aref(VALUE mod, VALUE key) 
{
  VALUE h = Qnil;
  ID mapping = rb_intern("@mapping");

  switch (TYPE(key)) {
    case T_SYMBOL:
      h = rb_ivar_get(capby_mConstantsDLT, mapping);
      mapping = Qnil;

      if (h == Qnil)
        rb_raise(rb_eRuntimeError, "ConstantDLT hash not set");

      return rb_hash_aref(h, key);
      break;
    case T_FIXNUM:
      return capby_DLT2SYM(NUM2INT(key));
      break;
    default:
      rb_raise(rb_eTypeError, "expecting Symbol or Fixnum");
      break;
  }
}

static VALUE capby_CST_DLT_all(VALUE mod) 
{
  ID mapping = rb_intern("@mapping");
  return rb_ivar_get(capby_mConstantsDLT, mapping);
}

static VALUE capby_DEV_all(VALUE class) 
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t * list = NULL;
  pcap_if_t * curr = NULL;
  VALUE o_device = Qnil;

  VALUE ary = rb_ary_new();

  if (pcap_findalldevs(&list, errbuf) < 0) {
    rb_raise(capby_eError, "%s", errbuf);
  } else {
    curr = list;
    while (curr != NULL) {
      pcap_if_t * p_device = curr ;

      o_device = Data_Wrap_Struct(class,
          __capby_DEV_mark_dev,
          __capby_DEV_free_dev,
          p_device);

      rb_ary_push(ary, o_device);

      //XXX: we rely on the GC to free the struct in time.
      curr = p_device->next;
      p_device->next = NULL;
    }
    curr = NULL;
    list = NULL;
  }

  return ary;
}

static void __capby_DEV_mark_dev(pcap_if_t* dev) 
{
  //do nothing
}

static void __capby_DEV_free_dev(pcap_if_t* dev) 
{
  pcap_freealldevs(dev);
}


static VALUE capby_DEV_get_name(VALUE self) 
{
  VALUE ret = rb_str_new2("");
  pcap_if_t * pDev = NULL;

  Data_Get_Struct(self, pcap_if_t, pDev);

  if (pDev == NULL) {
    rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
  } else if (pDev->name) {
    ret = rb_str_new2(pDev->name);
  }

  pDev = NULL;

  return ret;
}

static VALUE capby_DEV_get_desc(VALUE self) 
{
  VALUE ret = rb_str_new2("");
  pcap_if_t * pDev = NULL;

  Data_Get_Struct(self, pcap_if_t, pDev);

  if (pDev == NULL) {
    rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
  } else if (pDev->description) {
    ret = rb_str_new2(pDev->description);
  }

  pDev = NULL;

  return ret;
}

static VALUE capby_DEV_is_loopback(VALUE self) 
{
  VALUE ret = Qfalse;
  pcap_if_t * pDev = NULL;

  Data_Get_Struct(self, pcap_if_t, pDev);

  if (pDev == NULL) {
    rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    ret = Qnil;
  } else if (pDev->flags && PCAP_IF_LOOPBACK) {
    ret = Qtrue;
  }

  pDev = NULL;

  return ret;
}

static VALUE capby_DEV_get_addresses(VALUE self) 
{
  VALUE ret = Qfalse;
  pcap_if_t * pDev = NULL;

  Data_Get_Struct(self, pcap_if_t, pDev);

  if (pDev == NULL) {
    rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    ret = Qnil;
  } else {
    ret = rb_ary_new();
    struct pcap_addr * addr = NULL;

    for (addr = pDev->addresses; addr != NULL; addr = addr->next) {
      VALUE hash = rb_hash_new();
      rb_ary_push(ret, hash);
      /* XXX: note, we pack struct sockaddr into ruby strings
       *      - shall we do better? */
      /* addr */
      if (addr->addr != NULL)
        rb_hash_aset(hash, ID2SYM(rb_intern("addr")),
            rb_str_new((char*)addr->addr, sizeof(struct sockaddr)));
      /* netmask */
      if (addr->netmask != NULL)
        rb_hash_aset(hash, ID2SYM(rb_intern("netmask")),
            rb_str_new((char*)addr->netmask, sizeof(struct sockaddr)));
      /* broadaddr */
      if (addr->broadaddr != NULL)
        rb_hash_aset(hash, ID2SYM(rb_intern("broadaddr")),
            rb_str_new((char*)addr->broadaddr, sizeof(struct sockaddr)));
      /* dstaddr */
      if (addr->dstaddr != NULL)
        rb_hash_aset(hash, ID2SYM(rb_intern("dstaddr")),
            rb_str_new((char*)addr->dstaddr, sizeof(struct sockaddr)));
    }
  }

  pDev = NULL;

  return ret;
}

#ifdef HAVE_DNET_H
static VALUE capby_DEV_get_hw_address(VALUE self) 
{
  VALUE ret = Qnil;
  pcap_if_t * pDev = NULL;

  Data_Get_Struct(self, pcap_if_t, pDev);

  if (pDev == NULL) {
    rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    ret = Qnil;
  } else {
    if (pDev->name != NULL) {
      intf_t * iface_p = NULL;
      struct intf_entry iface;

      memset(&iface, '\0', sizeof(struct intf_entry));
      strncpy((char*)&iface.intf_name, pDev->name, INTF_NAME_LEN);

      iface_p = intf_open();
      if ((iface_p != NULL) && (! intf_get(iface_p, &iface))) {
        char * cStr = addr_ntoa(&iface.intf_link_addr);
        if (cStr != NULL)
          ret = rb_str_new2(cStr);
      }
      intf_close(iface_p);
      iface_p = NULL;
    }
  }

  pDev = NULL;

  return ret;
}
#endif

static void __capby_PKT_mark_packet(struct capby_packet * pkt)
{
  if (pkt == NULL)
    return;
  if (pkt->data != Qnil)
    rb_gc_mark(pkt->data);
  if (pkt->tst != Qnil)
    rb_gc_mark(pkt->tst);
}

static void __capby_PKT_free_packet(struct capby_packet * pkt)
{
  if (pkt == NULL)
    return;
  free(pkt);
}

static VALUE capby_PKT_new(VALUE class, VALUE data) 
{
  VALUE self = Qnil;
  struct capby_packet * pkt = NULL;

  Check_Type(data, T_STRING);

  self = Data_Make_Struct( class, struct capby_packet,
      __capby_PKT_mark_packet,
      __capby_PKT_free_packet, pkt);
  pkt->data = data;
  pkt->tst  = Qnil;

  if (pkt == NULL)
    rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);

  rb_iv_set(self, "@before_delay", INT2FIX(0));
  rb_iv_set(self, "@after_delay", INT2FIX(0));

  return self;
}

static VALUE capby_PKT_get_data(VALUE self)
{
  VALUE ret = Qnil;
  struct capby_packet * pkt = NULL;
  Data_Get_Struct(self, struct capby_packet, pkt);

  if (pkt == NULL)
    rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);

  ret = pkt->data;
  return ret;
}

static VALUE capby_PKT_get_tst(VALUE self)
{
  VALUE ret = Qnil;
  struct capby_packet * pkt = NULL;
  Data_Get_Struct(self, struct capby_packet, pkt);

  if (pkt == NULL)
    rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);

  ret = pkt->tst;
  return ret;
}

static VALUE __capby_PKT_from_pcap_data(const struct pcap_pkthdr * pkt_head,
    const u_char *data)
{
  VALUE pkt = Qnil;
  if (pkt_head->caplen > 0) {
    //TODO: clean that a bit
    VALUE str = Qnil;
    struct capby_packet * pPacket = NULL;

    str = rb_tainted_str_new((char*)data, pkt_head->caplen);
    pkt = capby_PKT_new(capby_cPacket, str);

    Data_Get_Struct(pkt, struct capby_packet, pPacket);
    if (pPacket == NULL)
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    pPacket->tst = rb_time_new(pkt_head->ts.tv_sec, pkt_head->ts.tv_usec);

  } else {
    rb_raise(capby_eError, "trying to create an empty pkt from Cdata");
  }
  return pkt;
}

#ifdef HAVE_QUERYPERFORMANCECOUNTER
LARGE_INTEGER Frequency = {0, 0};

void FrequencyInit()
{
  QueryPerformanceFrequency(&Frequency);
}

void SleepMicro(int micros)
{
  LARGE_INTEGER DepL;
  LARGE_INTEGER FinL;

  QueryPerformanceCounter(&DepL);
  QueryPerformanceCounter(&FinL);
  while (((FinL.QuadPart - DepL.QuadPart) * 1e6) <
      (Frequency.QuadPart * micros))
  {
    QueryPerformanceCounter(&FinL);
  }
}

#endif

static void wait_n_usecs(unsigned int usec)
{
#ifdef HAVE_NANOSLEEP
  struct timespec req, rem;

  if (usec == 0)
    return;

  memset(&req, '\0', sizeof(struct timespec));
  memset(&rem, '\0', sizeof(struct timespec));
  rem.tv_nsec = (long) usec * 1000;

  do { 
    memcpy(&req, &rem, sizeof(struct timespec));
  } while((nanosleep(&req, &rem) == -1) && (errno==EINTR));
#elif HAVE_QUERYPERFORMANCECOUNTER
  if ((int)(usec)>0)
    SleepMicro((int)usec);
#elif HAVE_SLEEP
  if ((int)(msec)>0)
    Sleep((int)msec/1000);
#else
  rb_warn("No function to sleep");
#endif
}

static VALUE capby_CAP_send_pkts(VALUE self, VALUE ary)
{
  long idx = 0;
  VALUE pkt = Qnil;
#ifndef RUBY_19
  int size = RARRAY(ary)->len;
#else
  long size = RARRAY_LEN(ary);
#endif

  Check_Type(ary, T_ARRAY);

  /* here we prefer to individually check all the packets in the array first,
   * then to send unchecked */
  for (idx=0; idx < size; idx++)
    Check_Type(rb_ary_entry(ary, idx), capby_cPacket);

  return capby_CAP_send_pkts_no_typecheck(self, ary);
}

static VALUE capby_CAP_send_pkts_no_typecheck(VALUE self, VALUE ary)
{
  long idx = 0;
  VALUE pkt = Qnil;
#ifndef RUBY_19
  int size = RARRAY(ary)->len;
#else
  long size = RARRAY_LEN(ary);
#endif
  for (idx=0; idx < size; idx++)
    capby_CAP_send_pkt_no_typecheck(self, rb_ary_entry(ary, idx));
  return Qnil;
}

static VALUE capby_CAP_send_pkt(VALUE self, VALUE rb_pkt)
{
    Check_Type(rb_pkt, capby_cPacket);
    capby_CAP_send_pkt_no_typecheck(self, rb_pkt);
}

static VALUE capby_CAP_send_pkt_no_typecheck(VALUE self, VALUE rb_pkt)
{
  struct capby_packet * pkt = NULL;
  struct capby_capture * capture = NULL;
  Data_Get_Struct(rb_pkt, struct capby_packet, pkt);
  Data_Get_Struct(self, struct capby_capture, capture);

  if ((capture == NULL) || (pkt == NULL)) {
    rb_warn("NULL pointer passed to %s", __FUNCTION__);
    return Qnil;
  } else {
    VALUE str = pkt->data;
    char * cStr = NULL;
#ifndef RUBY_19
    int cLen = 0;
    cStr = RSTRING(str)->ptr;
    cLen = RSTRING(str)->len;
#else
    long cLen = 0;
    cStr = RSTRING_PTR(str);
    cLen = RSTRING_LEN(str);
#endif

    wait_n_usecs(NUM2INT(rb_iv_get(rb_pkt, "@before_delay")));

#ifdef HAVE_PCAP_INJECT
    if (pcap_inject(capture->ctx, cStr, cLen) == -1) {
#elif defined HAVE_PCAP_SENDPACKET
      if (pcap_sendpacket(capture->ctx, cStr, cLen) == -1) {
#else
#error missing mandatory injection method here
#endif
        rb_warn("could not send packet");
      }

      wait_n_usecs(NUM2INT(rb_iv_get(rb_pkt, "@after_delay")));
    }
    return Qnil;
  }

  static VALUE capby_PKT_send_no_typecheck(VALUE self, VALUE cap) 
  {
    return capby_CAP_send_pkt_no_typecheck(cap, self);
  }

  static VALUE capby_PKT_send(VALUE self, VALUE cap) 
  {
    return capby_CAP_send_pkt(cap, self);
  }

  static void __capby_CAP_mark_capture(struct capby_capture * cap)
  {
    if (cap == NULL)
      return;
    if (cap->dev != Qnil)
      rb_gc_mark(cap->dev);
  }

  static void __capby_CAP_free_capture(struct capby_capture * cap)
  {
    if (cap == NULL)
      return;
    if (cap->ctx != NULL) {
      pcap_close(cap->ctx);
      cap->ctx = NULL;
    }
    free(cap);
  }

  static VALUE capby_CAP_new(VALUE class, VALUE dev) 
  {

    VALUE self = Qnil;
    struct capby_capture * capture = NULL;
    pcap_t * ctx = NULL;
    pcap_if_t * pDev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if ( CLASS_OF(dev) != capby_cDevice )
      rb_raise(rb_eArgError, "expecting a Capby::Device");

    Data_Get_Struct(dev, pcap_if_t, pDev);

    if (pDev == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    } else {
      ctx = pcap_open_live( pDev->name, CAPBY_DEFAULT_BUFLEN, 0, 0, errbuf);

      if (ctx == NULL) {
        rb_raise(capby_eError, "%s", errbuf);
        return Qnil;
      }

      self = Data_Make_Struct(class, struct capby_capture,
          __capby_CAP_mark_capture,
          __capby_CAP_free_capture, capture);
      if (capture == NULL)
        rb_raise(rb_eRuntimeError, "%s: NULL data pointer after alloc", __FUNCTION__);
      capture->ctx = ctx;
      capture->type = CAPBY_LIVE_CAPTURE;
      capture->dev = dev;
    }

    capby_CAP_set_direction(self, ID2SYM(rb_intern("both")));
    capby_CAP_set_blocking(self, Qfalse);

    return self;
  }

  static VALUE capby_CAP_new_for_file(VALUE class, VALUE filepath)
  {
    VALUE self = Qnil;
    struct capby_capture * capture = NULL;
    pcap_t * ctx = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    Check_Type(filepath, T_STRING);

#ifndef RUBY_19
    ctx = pcap_open_offline(RSTRING(filepath)->ptr, errbuf);
#else
    ctx = pcap_open_offline(RSTRING_PTR(filepath), errbuf);
#endif

    if (ctx == NULL) {
      rb_raise(capby_eError, "%s", errbuf);
      return Qnil;
    } else {
      self = Data_Make_Struct(class, struct capby_capture,
          __capby_CAP_mark_capture,
          __capby_CAP_free_capture, capture);

      if (capture == NULL)
        rb_raise(rb_eRuntimeError, "%s: NULL data pointer after alloc", __FUNCTION__);
      capture->dev = Qnil;
      capture->type = CAPBY_FILE_CAPTURE;
      capture->ctx = ctx;
    }

    return self;
  }

  static VALUE capby_CAP_set_snaplen(VALUE self, VALUE cnt) 
  {
    struct capby_capture * capture = NULL;

    Check_Type(cnt, T_FIXNUM);
    Data_Get_Struct(self, struct capby_capture, capture);
    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    } else {
#ifdef HAVE_PCAP_SET_SNAPLEN
      pcap_set_snaplen(capture->ctx, NUM2INT(cnt));
      return cnt;
#else
      rb_warn("no pcap_set_snaplen");
      return Qfalse;
#endif
    }
    return Qnil;
  }

  static VALUE capby_CAP_set_bufsize(VALUE self, VALUE cnt) 
  {
    struct capby_capture * capture = NULL;

    Check_Type(cnt, T_FIXNUM);
    Data_Get_Struct(self, struct capby_capture, capture);
    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    } else {
#ifdef HAVE_PCAP_SET_BUFFER_SIZE
      pcap_set_buffer_size(capture->ctx, NUM2INT(cnt));
      return cnt;
#else
      rb_warn("no pcap_set_buffer_size");
      return Qfalse;
#endif
    }
    return Qnil;
  }

  static VALUE capby_CAP_set_timeout(VALUE self, VALUE ms) 
  {
    struct capby_capture * capture = NULL;

    Check_Type(ms, T_FIXNUM);
    Data_Get_Struct(self, struct capby_capture, capture);
    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    } else {
#ifdef HAVE_PCAP_SET_TIMEOUT
      pcap_set_timeout(capture->ctx, NUM2INT(ms));
      return ms;
#else
      rb_warn("no pcap_set_timeout");
      return Qfalse;
#endif
    }
    return Qnil;
  }


  static VALUE capby_CAP_get_blocking(VALUE self)
  {
    VALUE ret = Qnil;
    struct capby_capture * capture = NULL;
    Data_Get_Struct(self, struct capby_capture, capture);
    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    } else {
      char errbuf[PCAP_ERRBUF_SIZE];
      int block_mode;

      block_mode = pcap_getnonblock(capture->ctx, errbuf);
      //rb_warn("pcap nonblocking mode is %d", block_mode);

      if (block_mode == -1) {
        rb_raise(capby_eError, "%s", errbuf);
      } else {
        if (block_mode == 0)
          ret = Qtrue;
        else
          ret = Qfalse;
      }
    }

    return ret;
  }

  static VALUE capby_CAP_set_blocking(VALUE self, VALUE mode)
  {
    struct capby_capture * capture = NULL;
    Data_Get_Struct(self, struct capby_capture, capture);
    int block_mode;

    if (mode == Qtrue)
      block_mode = 0;
    else
      block_mode = 1;

    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    } else {
      char errbuf[PCAP_ERRBUF_SIZE];
      int i;

      i = pcap_setnonblock(capture->ctx, block_mode, errbuf);

      if (i == -1) {
        rb_raise(capby_eError, "%s", errbuf);
        return Qfalse;
      } else {
        int new_block_mode = pcap_getnonblock(capture->ctx, errbuf);
        if (new_block_mode != block_mode)
          rb_warn("non blocking mode set to %d instead of %d", new_block_mode, block_mode);

      }
    }

    return Qtrue;
  }

  static VALUE capby_CAP_get_direction(VALUE self)
  {
    struct capby_capture * capture = NULL;
    Data_Get_Struct(self, struct capby_capture, capture);
    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
      return Qnil;
    }

    return rb_ivar_get(self, rb_intern("@direction"));
  }

  static VALUE capby_CAP_set_direction(VALUE self, VALUE mode)
  {
    pcap_direction_t dir = PCAP_D_INOUT;
    struct capby_capture * capture = NULL;
    Data_Get_Struct(self, struct capby_capture, capture);

    if (rb_to_id(mode) == rb_intern("both"))
      dir = PCAP_D_INOUT;
    else if (rb_to_id(mode) == rb_intern("in"))
      dir = PCAP_D_IN;
    else if (rb_to_id(mode) == rb_intern("out"))
      dir = PCAP_D_OUT;
    else
      rb_raise(rb_eArgError, "direction should be :both, :out, or :in");

    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    } else {
#ifdef HAVE_PCAP_SETDIRECTION
      int i = pcap_setdirection(capture->ctx, dir);
      if (i == -1) {
        char errbuf[PCAP_ERRBUF_SIZE];
        strncpy(errbuf, pcap_geterr(capture->ctx), PCAP_ERRBUF_SIZE);
        errbuf[PCAP_ERRBUF_SIZE-1] = '\0';
        rb_raise(capby_eError, "%s", errbuf);
        return Qfalse;
      } else {
        rb_ivar_set(self, rb_intern("@direction"), mode);
        return mode;
      }
#else
      rb_warn("no pcap_setdirection");
      return Qfalse;
#endif
    }

    return Qtrue;
  }

  static VALUE capby_CAP_get_filter(VALUE self)
  {
    return rb_ivar_get(self, rb_intern("@filter"));
  }

  static VALUE capby_CAP_set_filter(int argc, VALUE * args, VALUE self)
  {
    int i;
    struct bpf_program fp;
    VALUE filter = Qnil;
    VALUE netmask = INT2NUM(0);

    struct capby_capture * capture = NULL;
    Data_Get_Struct(self, struct capby_capture, capture);
    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
      return Qnil;
    }

    switch (argc) {
      case 2:
        netmask = args[1];
        /* don't break */
      case 1:
        filter = args[0];
        if (filter == Qnil)
          filter = rb_str_new2("");

        break;
      default:
        rb_raise(rb_eArgError,
            "wrong number of arguments: %d instead of 1 or 2", argc);
        break;

    }

    Check_Type(filter, T_STRING);
    Check_Type(netmask, T_FIXNUM);

    i = pcap_compile(capture->ctx, &fp, RSTRING_PTR(filter), 
        1, NUM2INT(netmask));
    if (i == -1) {
      char errbuf[PCAP_ERRBUF_SIZE];
      strncpy(errbuf, pcap_geterr(capture->ctx), PCAP_ERRBUF_SIZE);
      errbuf[PCAP_ERRBUF_SIZE-1] = '\0';
      rb_raise(capby_eError, "%s", errbuf);
      return Qfalse;
    }

    i = pcap_setfilter(capture->ctx, &fp);

    if (i == -1) {
      char errbuf[PCAP_ERRBUF_SIZE];
      strncpy(errbuf, pcap_geterr(capture->ctx), PCAP_ERRBUF_SIZE);
      errbuf[PCAP_ERRBUF_SIZE-1] = '\0';
      rb_raise(capby_eError, "%s", errbuf);
      return Qfalse;
    }
    //XXX clean redundancies in rb_raise ... errbuf  => static function

    rb_ivar_set(self, rb_intern("@filter"), args[0]);
    return Qtrue;
  }

  static VALUE capby_CAP_each(int argc, VALUE * args, VALUE self)
  {
    VALUE ary = rb_ary_new2(2);
    VALUE max = INT2FIX(0);
    switch (argc) {
      case 0:
        break;
      case 1:
        max = args[0];
        break;
      default:
        rb_raise(rb_eArgError,
            "wrong number of arguments: %d instead of 0 or 1", argc);
        break;

    }
    rb_ary_push(ary, self);
    rb_ary_push(ary, max);

#ifdef HAVE_TRAP_BEG_M
#ifndef RUBY_19
    //rb_warn("> trap_beg %s", __FUNCTION__);
    TRAP_BEG;
    //rb_warn("< trap_beg %s", __FUNCTION__);
#endif
#endif
    rb_ensure(__capby_CAP_each, ary,
        __capby_CAP_each_ensure, self);
#ifdef HAVE_TRAP_END_M
#ifndef RUBY_19
    //rb_warn("> trap_end %s", __FUNCTION__);
    TRAP_END;
    //rb_warn("< trap_end %s", __FUNCTION__);
#endif
#endif
    return Qnil;
  }

  static VALUE __capby_CAP_each_ensure(VALUE self)
  {
    //rb_warn("%s", __FUNCTION__);
    return Qnil;
  }

  static VALUE __capby_CAP_each(VALUE ary)
  {
    VALUE self = Qnil;
    VALUE max = Qnil;
    int i, max_i;

    //rb_warn("%s", __FUNCTION__);
    /* assigning variables safely */
    Check_Type(ary, T_ARRAY);

    self = rb_ary_shift(ary);
    if ( (CLASS_OF(self) != capby_cLiveCapture) && 
        CLASS_OF(self) != capby_cFileCapture )
      rb_raise(rb_eArgError, "expecting a Capby::Capture");

    max = rb_ary_shift(ary);
    Check_Type(max, T_FIXNUM);
    max_i = NUM2INT(max);

    /* entering loop 
     * - max_i iterations
     * - or infinite loop if 0
     */   
    for (i=0; (i < max_i) || (max_i == 0); i++) {
      VALUE pkt = capby_CAP_next_packet(self);
      rb_yield( pkt );
    }

    return Qnil;
  }

  static VALUE capby_CAP_next_packet(VALUE self)
  {
    VALUE ret = Qnil;
    struct capby_capture * capture = NULL;
    Data_Get_Struct(self, struct capby_capture, capture);

    //rb_warn("%s", __FUNCTION__);
    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    } else {
      const u_char *data = NULL;
      struct pcap_pkthdr pkt_head;
      memset(&pkt_head, '\0', sizeof(struct pcap_pkthdr));
#ifdef HAVE_PCAP_GET_SELECTABLE_FD
#ifdef HAVE_RB_THREAD_WAIT_FD
      do {
        int fd = pcap_get_selectable_fd(capture->ctx);
        if (fd != -1) {
          //rb_warn("waiting for fd");
          rb_thread_wait_fd(fd);
          //rb_warn("fd ready");
        } else {
          rb_warn("no fd to select on");
        }
      }while (0);
#endif
#endif
      /* performs a blocking call to a C lib */
      data = pcap_next(capture->ctx, &pkt_head);
      if (data != NULL)
        ret = __capby_PKT_from_pcap_data(&pkt_head, data);
      //TODO: else raise an error if any (none in non blockmode)
    }
    return ret;
  }

  static VALUE capby_CAP_get_dlt(VALUE self)
  {
    VALUE ret = Qnil;
    struct capby_capture * capture = NULL;
    Data_Get_Struct(self, struct capby_capture, capture);
    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    } else {
      ret = capby_DLT2SYM(pcap_datalink(capture->ctx));
    }

    return ret;
  }

  static VALUE capby_CAP_get_stats(VALUE self)
  {
    VALUE ret = Qnil;
    struct capby_capture * capture = NULL;
    Data_Get_Struct(self, struct capby_capture, capture);
    if (capture == NULL) {
      rb_raise(rb_eRuntimeError, "%s: NULL data pointer", __FUNCTION__);
    } else {
      int ctrl;
      struct pcap_stat stats;
      ctrl = pcap_stats(capture->ctx, &stats);

      if (ctrl == -1) {
      } else {
        ret = rb_hash_new();
        rb_hash_aset(ret, ID2SYM(rb_intern("received")),
            INT2NUM(stats.ps_recv));
        rb_hash_aset(ret, ID2SYM(rb_intern("dropped")),
            INT2NUM(stats.ps_drop));
        rb_hash_aset(ret, ID2SYM(rb_intern("if_dropped")),
            INT2NUM(stats.ps_ifdrop));
#ifdef HAVE_ST_BS_CAPT
        rb_hash_aset(ret, ID2SYM(rb_intern("bs_capt")),
            INT2NUM(stats.bs_capt));
#endif
      }
    }
    return ret;
  }

  /* Initializations */

  void Init_capby_api( void ) 
  {

    /* Modules & classes */
    capby_mCapby = rb_define_module("Capby");
    capby_mConstants = rb_define_module_under(capby_mCapby, "Constants");
    capby_mConstantsDLT = rb_define_module_under(capby_mConstants, "DataLayerTypes");
    capby_cDevice = rb_define_class_under(capby_mCapby, "Device", rb_cObject);
    capby_cCapture = rb_define_class_under(capby_mCapby, "Capture", rb_cObject);
    capby_cLiveCapture = rb_define_class_under(capby_mCapby, "LiveCapture", capby_cCapture);
    capby_cFileCapture = rb_define_class_under(capby_mCapby, "FileCapture", capby_cCapture);
    capby_eError = rb_define_class_under(capby_mCapby, "CapbyError", rb_eStandardError);
    capby_cPacket = rb_define_class_under(capby_mCapby, "Packet", rb_cObject);

    /* General constants */
    __capby_init_CST();
    /* Datalink layer constants */
    __capby_init_CST_DLT();
    /* Devices methods */
    __capby_init_DEV();
    /* Capture methods */
    __capby_init_CAP();
    /* Packet methods */
    __capby_init_PKT();

    /* Ensure correctness of binary version (for ppl that redistributes binaries)*/
    __capby_check_binary();
  }

#define CAPBY_MSG_SIZE 1024
  static void __capby_check_binary_version( const char * cst, VALUE val1, VALUE val2 ) 
  {
    char msg[CAPBY_MSG_SIZE];
    memset(msg,'\0', CAPBY_MSG_SIZE);

    if (cst == NULL) {
      rb_warn("NULL pointer given to %s", __FUNCTION__);
      return;
    }

    Check_Type(val1, T_STRING);
    Check_Type(val2, T_STRING);

    snprintf((char*) msg, (size_t) CAPBY_MSG_SIZE, 
        "Binary verification failed for %s:\n got <%s> when compiling this extension and <%s> in environment", cst,
        StringValueCStr(val1),
        StringValueCStr(val2)
        );

    capby_warn_not_equal(val1, val2, (const char*) msg);
  }
#undef CAPBY_MSG_SIZE

  static void __capby_check_binary( void )
  {
    ID cst = Qnil;
    VALUE val1 = Qnil;
    VALUE val2 = Qnil;
    struct __capby_version_record * tst = NULL;

    for (tst = __capby_version_records; tst->cst != NULL; tst++) {
      cst = rb_intern(tst->cst);
      val1 = rb_str_new2(tst->val);
      val2 = rb_ivar_get(capby_mConstants, cst);
      __capby_check_binary_version( tst->cst, val1, val2 );
    }

    /* additional test */
    cst = rb_intern("PCAP_VERSION");
    val1 = rb_str_new2( pcap_lib_version() );
    val2 = rb_ivar_get(capby_mConstants, cst);
    __capby_check_binary_version( "PCAP_VERSION", val1, val2 );

    cst = Qnil;
    val1 = Qnil;
    val2 = Qnil;
  }

  static void __capby_init_CST( void ) 
  {
    ID cst = Qnil;
    VALUE val = Qnil;
    struct __capby_version_record * tst = NULL;

    for (tst = __capby_version_records; tst->cst != NULL; tst++) {
      cst = rb_intern(tst->cst);
      val = rb_str_new2(tst->val);
      rb_ivar_set(capby_mConstants, cst, val);
    }
    tst = NULL;

    /* additional test */
    cst = rb_intern("PCAP_VERSION");
    val = rb_str_new2( pcap_lib_version() );
    rb_ivar_set(capby_mConstants, cst, val);

    cst = Qnil;
    val = Qnil;
  }

  static void __capby_init_CST_DLT_mapping( void ) 
  {
    struct capby_datalink_triolet * curr = NULL;

    for (curr=capby_datalink_mapping; curr->name != NULL; curr++)
      curr->sym = ID2SYM(rb_intern( curr->name ));

    curr = NULL;
  }

  static void __capby_init_CST_DLT( void ) 
  {
    struct capby_datalink_triolet * curr = NULL;
    ID mapping = rb_intern("@mapping");
    VALUE h = Qnil;

    __capby_init_CST_DLT_mapping();

    if (rb_ivar_get(capby_mConstantsDLT, mapping) != Qnil)
      rb_warn("DLT constants will be overwritten");


    h = rb_hash_new();
    rb_ivar_set(capby_mConstantsDLT, mapping, h);

    mapping = Qnil;

    for (curr=capby_datalink_mapping; curr->name != NULL; curr++)
      rb_hash_aset(h, curr->sym, INT2NUM(curr->idx));

    curr = NULL;
    h = Qnil;

    /*methods*/
    rb_define_singleton_method(capby_mConstantsDLT, "[]", capby_CST_DLT_aref , 1);
    rb_define_singleton_method(capby_mConstantsDLT, "all", capby_CST_DLT_all , 0);

  }

  static void __capby_init_DEV( void )
  {
    /*methods*/
    rb_define_singleton_method(capby_cDevice, "all", capby_DEV_all , 0);
    rb_define_method(capby_cDevice, "name", capby_DEV_get_name, 0);
    rb_define_method(capby_cDevice, "desc", capby_DEV_get_desc, 0);
    rb_define_method(capby_cDevice, "loopback?", capby_DEV_is_loopback, 0);
    rb_define_method(capby_cDevice, "addresses", capby_DEV_get_addresses, 0);
#ifdef HAVE_DNET_H
    rb_define_method(capby_cDevice, "link_address", capby_DEV_get_hw_address, 0);
#endif
  }

  static void __capby_init_CAP( void ) 
  {
    /*methods*/

    rb_define_method(capby_cCapture, "each", capby_CAP_each, -1);
    rb_define_method(capby_cCapture, "next", capby_CAP_next_packet, 0);

    rb_define_singleton_method(capby_cLiveCapture, "new", capby_CAP_new, 1);
    rb_define_method(capby_cCapture, "datalink", capby_CAP_get_dlt, 0);
    rb_define_method(capby_cCapture, "stats", capby_CAP_get_stats, 0);
    rb_define_method(capby_cCapture, "blocking?", capby_CAP_get_blocking, 0);
    rb_define_method(capby_cCapture, "blocking=", capby_CAP_set_blocking, 1);
    rb_define_method(capby_cCapture, "snaplen=", capby_CAP_set_snaplen, 1);
    rb_define_method(capby_cCapture, "bufsize=", capby_CAP_set_bufsize, 1);
    rb_define_method(capby_cCapture, "timeout=", capby_CAP_set_timeout, 1);

    rb_define_singleton_method(capby_cFileCapture, "new", capby_CAP_new_for_file, 1);
    rb_define_method(capby_cLiveCapture, "direction", capby_CAP_get_direction, 0);
    rb_define_method(capby_cLiveCapture, "direction=", capby_CAP_set_direction, 1);

    rb_define_method(capby_cLiveCapture, "filter", capby_CAP_get_filter, 0);
    rb_define_method(capby_cLiveCapture, "filter=", capby_CAP_set_filter, -1);
    rb_define_method(capby_cLiveCapture, "send_packet", capby_CAP_send_pkt, 1);
    rb_define_method(capby_cLiveCapture, "send_packets", capby_CAP_send_pkts, 1);
    rb_define_method(capby_cLiveCapture, "send_packet!", capby_CAP_send_pkt_no_typecheck, 1);
    rb_define_method(capby_cLiveCapture, "send_packets!", capby_CAP_send_pkts_no_typecheck, 1);
  }

  static void __capby_init_PKT( void ) 
  {
    /*methods*/
    rb_define_singleton_method(capby_cPacket, "new", capby_PKT_new, 1);
    rb_define_method(capby_cPacket, "data", capby_PKT_get_data, 0);
    rb_define_method(capby_cPacket, "timestamp", capby_PKT_get_tst, 0);
    rb_define_method(capby_cPacket, "send_on", capby_PKT_send, 1);
    rb_define_method(capby_cPacket, "send_on!", capby_PKT_send_no_typecheck, 1);
    rb_define_attr(capby_cPacket, "before_delay", 1, 1);
    rb_define_attr(capby_cPacket, "after_delay", 1, 1);
  }

