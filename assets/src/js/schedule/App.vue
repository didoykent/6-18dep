<template>
  <v-app>
    <v-card>
    <v-card-title>
      Today {{new Date()}}

    </v-card-title>
    <v-data-table
      :headers="headers"
      :items="desserts"
      :search="search"
    >

    <template v-slot:item.calories="{ item }">

    <v-chip    label color="green" dark>
    <v-icon left color="red">mdi-video</v-icon>
      {{ item.calories }} </v-chip>
  </template>



  <template v-slot:item.fat="{ item }">

  <v-chip color="red" dark>
      <v-icon left color="green">mdi-phone</v-icon>
    {{ item.fat }}</v-chip>
</template>

<template v-slot:item.carbs="{ item }">
<v-chip color="orange" dark>{{ item.carbs }}</v-chip>
</template>

<template v-slot:item.protein="{ item }">
<v-chip color="pink" dark>{{ item.protein }}</v-chip>
</template>

<template v-slot:item.iron="{ item }">
<v-chip color="blue" dark>

  {{ item.iron }}</v-chip>
</template>
    </v-data-table>
  </v-card>
  </v-app>
</template>

<script>
  export default {
    data () {
      return {
        search: '',
        headers: [
          {
            text: '',
            align: 'center',
            sortable: false,
            value: 'name',



          },

          { text: '10', value: 'calories',   align: 'center', },
          { text: '20', value: 'fat',   align: 'center', },
          { text: '30', value: 'carbs',   align: 'center', },
          { text: '40', value: 'protein',   align: 'center', },
          { text: '50', value: 'iron',   align: 'center', },
        ],
        desserts: [
          {
            name: 1,
            calories: 'Jennie',

            fat: 'Jennie',
            carbs: 'Jennie',
            protein: 'Jennie',
            iron: 'Jennie',
          },
          {
            name: 2,
            calories: 'Kim',
            fat: 'Kim',
            carbs: 'Kim',
            protein:'Kim',
            iron: 'Kim',
          },
          {
            name: 3,
            calories: 'Seo Hyun',
            fat: 'Seo Hyun',
            carbs: 'Seo Hyun',
            protein: 'Seo Hyun',
            iron: 'Seo Hyun',
          },
          {
            name: 4,
            calories: 'Lisa',
            fat: 'Lisa',
            carbs: 'Lisa',
            protein: 'Lisa',
            iron: 'Lisa',
          },
          {
            name: 5,
            calories: 'Chaeyoung',
            fat: 'Chaeyoung',
            carbs: 'Chaeyoung',
            protein: 'Chaeyoung',
            iron: 'Chaeyoung',
          },

        ],
      }
    },
  }
</script>

<style>

</style>
