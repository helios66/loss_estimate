#ifndef REPORT_H
#define REPORT_H

void report_alert(struct ear *ear, struct ear_alert *result, struct cache_entry *cache_entry);
void report_tracked(struct ear *ear, uint32_t hash, int offset, struct hdr flow);
void report_attack(struct ear *ear, struct hdr *t);
void report_stats(struct ear *ear, struct ear_stats *stats);
void report_summary(struct ear *ear, struct ear_stats *stats);
void report_sled(struct hdr addr);

#endif
