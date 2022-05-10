import numpy as np, pandas as pd, seaborn as sns, matplotlib.pyplot as plt
from sklearn.datasets import make_blobs
from sklearn.datasets import make_moons
def GUC_Distance ( Cluster_Centroids, Data_points, Distance_Type ):
## write code here for the Distance function here #
    Cluster_Distance=np.zeros(shape=(Data_points.shape[0], Cluster_Centroids.shape[0]))
    for i in range(Data_points.shape[0]):
        Data_point=Data_points[i].reshape(1,Data_points[i].shape[0])
        if Distance_Type=="Ecluidian":
            Cluster_Distance[i]=np.sqrt(np.sum(np.square(Cluster_Centroids-Data_point),axis=1))
        if Distance_Type == 'Pearson':
            Cluster_Distance[i]=np.sum(np.abs(Cluster_Centroids-Data_point),axis=1)
    return Cluster_Distance


def GUC_Kmean(Data_points, Number_of_Clusters, Distance_Type):
    # write code for intial cluster heads here
    # write your your loop
    Cluster_Centroids = Data_points[
        np.random.choice([i for i in range(Data_points.shape[0])], Number_of_Clusters, replace=False)]
    old_mean = 1
    new_mean = .1
    
    while new_mean / old_mean < 0.999 or new_mean / old_mean > 1:
        Cluster_Distance = GUC_Distance(Cluster_Centroids, Data_points, Distance_Type)
        clusters_min_num = np.argmin(Cluster_Distance, axis=1) # to return the index of the minimum value
        new_clusters = np.zeros((Number_of_Clusters, Data_points.shape[1])) # matrix for the new clusters
        npoints = np.zeros((Number_of_Clusters, 1))
        # The enumerate() function assigns an index to each item
        for index, p in enumerate(clusters_min_num):
            npoints[p] = npoints[p] + 1
            new_clusters[p] = new_clusters[p] + Data_points[index]

        new_clusters = new_clusters / (npoints + pow(10, -11))
        price = 0
        for index, p in enumerate(clusters_min_num):
            price += np.sum(np.square(new_clusters[p] - Data_points[index]))
        old_mean = new_mean
        new_mean = np.sqrt(price) / len(Data_points)
        Cluster_Centroids = new_clusters
    output = {'cluster_centers_': Cluster_Centroids, 'labels_': clusters_min_num}


    return [Cluster_Centroids, output]

