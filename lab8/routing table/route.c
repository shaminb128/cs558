#include "route.h"


int createRT()
{
    short int metric;
    char dest[50], gw[50], mask[50], dev[50];
    rt_table rt_tbl;
    rt_table *pointer;

    rt_tbl_list = NULL;

    FILE *fp = fopen("routing table.txt", "r");
    if (fp == NULL) {
        fprintf(stderr, "Can't open input!\n");
        exit(1);
    }
    char line[250];
    //read first line
    fgets(line, 250, fp);
    rt_tbl_list = malloc(sizeof(struct rttable));
    pointer = rt_tbl_list;
    total_tbl_size = 0;
    while(!feof(fp)){
        if(fscanf(fp, "%s\t%s\t%s\t%hd\t%s", dest, gw, mask, &metric, dev)){
            inet_pton(AF_INET, dest, &(pointer->rt_dst.sin_addr));
            inet_pton(AF_INET, gw, &(pointer->rt_gateway.sin_addr));
            inet_pton(AF_INET, mask, &(pointer->rt_genmask.sin_addr));
            pointer->rt_metric = metric;
            memcpy(pointer->rt_dev, dev, strlen(dev) + 1);
            pointer->next = malloc(sizeof(struct rttable));
            pointer = pointer->next;
            total_tbl_size ++;
        }
        else
            break;
    }
    printf("Routing table created\n");
    pointer = NULL;
    free(pointer);


    fclose(fp);
    return 0;

}


int printRT(rt_table *rt_list)
{
    short int metric;
    char dest[50], gw[50], mask[50], dev[50];
    rt_table *pointer;

    pointer = rt_list;

    while(pointer != NULL){

        inet_ntop(AF_INET, &(pointer->rt_dst.sin_addr), dest, 50);
        inet_ntop(AF_INET, &(pointer->rt_gateway.sin_addr), gw, 50);
        inet_ntop(AF_INET, &(pointer->rt_genmask.sin_addr), mask, 50);
        printf("Dest: %s, GW: %s, Mask : %s, Metric: %hd, Device: %s\n",dest, gw, mask, pointer->rt_metric, pointer->rt_dev);
        pointer = pointer->next;
    }

    return 0;

}



