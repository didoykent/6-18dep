<template>
  <v-container>

    <v-row>
      <v-col :cols="leftColumn">
        <v-card flat style="width:100%;height:100%">
          <v-container>
            <v-row>
              <iframe class="iframe-placeholder" src="http://178.128.213.14/" style="height:600px;width:92%"></iframe>
              <v-spacer></v-spacer>
              <v-icon large color="primary" @click="showMenu">{{arrow}}</v-icon>
            </v-row>
          </v-container>
        </v-card>
      </v-col>
      <v-col :cols="rightColumn">
        <v-card :style="rightStyle">
          <v-card-title class="headline">
            <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
            background-color:#E91E63;">
            <v-icon color="white" x-large>check</v-icon>
          </div>
          Student's Evaluation
        </v-card-title>
        <v-stepper v-model="stepper" alt-labels flat>
          <v-stepper-header>
            <v-stepper-step :complete="stepper > 1" step="1">Content</v-stepper-step>
            <v-divider></v-divider>
            <v-stepper-step :complete="stepper > 2" step="2">Scores</v-stepper-step>
            <v-divider></v-divider>
            <v-stepper-step step="3">Memo</v-stepper-step>
          </v-stepper-header>

          <v-stepper-items>
            <v-stepper-content step="1">
              <v-container>
                <v-row>
                  <v-col cols="12">
                    <v-select label="Attendance"  v-model = "Attendance" :items="attendance"></v-select>
                  </v-col>
                </v-row>
                <v-row class="mb-4">
                  <v-col cols="12" md="6">
                    <v-text-field label="Topic" v-model = "Lesson" regular></v-text-field>
                  </v-col>
                  <v-col cols="12" md="6">
                    <v-text-field label="Page Number"   v-model = "pageNumber" regular></v-text-field>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="12">
                    <v-text-field label="Corrected Sentence 1" v-model = "Corrected1" regular></v-text-field>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="12">
                    <v-text-field label="Corrected Sentence 2" v-model = "Corrected2"  regular></v-text-field>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="10">
                    <v-text-field v-model="word1" :loading="loading1" label="Word of the Day 1" regular></v-text-field>
                  </v-col>
                  <v-col cols="2" class="pb-0">
                    <button class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                      <v-icon @click="getDefinition1()" color="white" x-large>search</v-icon>
                    </button>
                  </v-col>
                  <v-container v-if="transcript1 != ''" class="py-0">
                    <v-row>
                      <v-col cols="12" class="py-0">
                        <v-card flat>{{transcript1}}</v-card>
                      </v-col>
                    </v-row>
                    <v-divider class="my-0"></v-divider>
                    <v-tabs v-model="tab1" class="mb-2">
                      <v-tab v-for="item in tabArray1" :key="item">{{item}}</v-tab>
                      <v-tab-item class="mt-2" v-for="item in tabArray1" :key="item">
                        <v-expansion-panels>
                          <v-expansion-panel v-if="item == 'noun'" v-for="noun in nounArray" :key="noun">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected" :value="item" ></v-checkbox>
                              </v-col>
                              {{noun.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof noun.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{noun.example}}</span>
                              <br />
                              <span v-if="typeof noun.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in noun.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'verb'" v-for="verb in verbArray" :key="verb">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected" :value="item" ></v-checkbox>
                              </v-col>
                              {{verb.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof verb.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{verb.example}}</span>
                              <br />
                              <span v-if="typeof verb.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in verb.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'adverb'" v-for="adverb in adverbArray" :key="adverb">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected" :value="item" ></v-checkbox>
                              </v-col>
                              {{adverb.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof adverb.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{adverb.example}}</span>
                              <br />
                              <span v-if="typeof adverb.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in adverb.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'adjective'" v-for="adjective in adjectiveArray" :key="adjective">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected" :value="item" ></v-checkbox>
                              </v-col>
                              {{adjective.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof adjective.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{adjective.example}}</span>
                              <br />
                              <span v-if="typeof adjective.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in adjective.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'pronoun'" v-for="pronoun in pronounArray" :key="pronoun">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected" :value="item" ></v-checkbox>
                              </v-col>
                              {{pronoun.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof pronoun.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{pronoun.example}}</span>
                              <br />
                              <span v-if="typeof pronoun.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in pronoun.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'preposition'" v-for="preposition in prepositionArray" :key="preposition">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkboxv-model = "speechSelected" :value="item" ></v-checkbox>
                              </v-col>
                              {{preposition.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof preposition.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{preposition.example}}</span>
                              <br />
                              <span v-if="typeof preposition.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in preposition.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'conjunction'" v-for="conjunction in conjunctionArray" :key="conjunction">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected" :value="item" ></v-checkbox>
                              </v-col>
                              {{conjunction.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof conjunction.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{conjunction.example}}</span>
                              <br />
                              <span v-if="typeof conjunction.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in conjunction.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'determiner'" v-for="determiner in determinerArray" :key="determiner">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected" :value="item" ></v-checkbox>
                              </v-col>
                              {{determiner.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof determiner.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{determiner.example}}</span>
                              <br />
                              <span v-if="typeof determiner.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in determiner.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'exclamation'" v-for="exclamation in exclamationArray" :key="exclamation">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected" :value="item"></v-checkbox>
                              </v-col>
                              {{exclamation.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof exclamation.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{exclamation.example}}</span>
                              <br />
                              <span v-if="typeof exclamation.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in exclamation.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>

                        </v-expansion-panels>
                      </v-tab-item>
                    </v-tabs>
                  </v-container>
                </v-row>
                <v-row>
                  <v-col cols="10">
                    <v-text-field v-model="word2" :loading="loading2" label="Word of the Day 2" regular></v-text-field>
                  </v-col>
                  <v-col cols="2">
                    <button @click="getDefinition2()" class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                      <v-icon color="white" x-large>search</v-icon>
                    </button>
                  </v-col>
                  <v-container v-if="transcript2 != ''" class="py-0">
                    <v-row>
                      <v-col cols="12" class="py-0">
                        <v-card flat>{{transcript2}}</v-card>
                      </v-col>
                    </v-row>
                    <v-divider class="my-0"></v-divider>
                    <v-tabs v-model="tab2" class="mb-2">
                      <v-tab v-for="item in tabArray2" :key="item">{{item}}</v-tab>
                      <v-tab-item class="mt-2" v-for="item in tabArray2" :key="item">
                        <v-expansion-panels>
                          <v-expansion-panel v-if="item == 'noun'" v-for="noun in nounArray2" :key="noun">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected2" :value="item" ></v-checkbox>
                              </v-col>
                              {{noun.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof noun.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{noun.example}}</span>
                              <br />
                              <span v-if="typeof noun.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in noun.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'verb'" v-for="verb in verbArray2" :key="verb">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected2" :value="item"></v-checkbox>
                              </v-col>
                              {{verb.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof verb.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{verb.example}}</span>
                              <br />
                              <span v-if="typeof verb.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in verb.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'adverb'" v-for="adverb in adverbArray2" :key="adverb">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected2" :value="item"></v-checkbox>
                              </v-col>
                              {{adverb.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof adverb.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{adverb.example}}</span>
                              <br />
                              <span v-if="typeof adverb.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in adverb.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'adjective'" v-for="adjective in adjectiveArray2" :key="adjective">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected2" :value="item"></v-checkbox>
                              </v-col>
                              {{adjective.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof adjective.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{adjective.example}}</span>
                              <br />
                              <span v-if="typeof adjective.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in adjective.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'pronoun'" v-for="pronoun in pronounArray2" :key="pronoun">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected2" :value="item"></v-checkbox>
                              </v-col>
                              {{pronoun.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof pronoun.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{pronoun.example}}</span>
                              <br />
                              <span v-if="typeof pronoun.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in pronoun.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'preposition'" v-for="preposition in prepositionArray2" :key="preposition">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected2" :value="item"></v-checkbox>
                              </v-col>
                              {{preposition.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof preposition.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{preposition.example}}</span>
                              <br />
                              <span v-if="typeof preposition.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in preposition.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'conjunction'" v-for="conjunction in conjunctionArray2" :key="conjunction">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected2" :value="item"></v-checkbox>
                              </v-col>
                              {{conjunction.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof conjunction.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{conjunction.example}}</span>
                              <br />
                              <span v-if="typeof conjunction.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in conjunction.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'determiner'" v-for="determiner in determinerArray2" :key="determiner">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected2" :value="item"></v-checkbox>
                              </v-col>
                              {{determiner.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof determiner.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{determiner.example}}</span>
                              <br />
                              <span v-if="typeof determiner.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in determiner.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>
                          <v-expansion-panel v-if="item == 'exclamation'" v-for="exclamation in exclamationArray2 " :key="exclamation">
                            <v-expansion-panel-header>
                              <v-col cols="1">
                                <v-checkbox v-model = "speechSelected2" :value="item"></v-checkbox>
                              </v-col>
                              {{exclamation.definition}}
                            </v-expansion-panel-header>
                            <v-expansion-panel-content>
                              <span v-if="typeof exclamation.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{exclamation.example}}</span>
                              <br />
                              <span v-if="typeof exclamation.synonyms != 'undefined'">
                                <br />
                                <span class="font-weight-medium">Synonyms:</span>
                                <span v-for="synonym in exclamation.synonyms" :key="synonym">{{synonym}}<br /></span>
                              </span>
                            </v-expansion-panel-content>
                          </v-expansion-panel>

                        </v-expansion-panels>
                      </v-tab-item>
                    </v-tabs>
                  </v-container>
                </v-row>
                <v-row class="d-flex justify-content-end">
                  <v-btn text>Close</v-btn>
                  <v-btn @click="stepper = 2" color="#E91E63" class="white--text">Next</v-btn>
                </v-row>
              </v-container>
            </v-stepper-content>
            <v-stepper-content step="2">
              <v-container>
                <v-row>
                  <v-col cols="12" md="6">
                    <v-select label="Pronunciation"   v-model = "Pronunciation" :items="scores"></v-select>
                  </v-col>
                  <v-col cols="12" md="6">
                    <v-select label="Grammar"  v-model = "Grammar" :items="scores"></v-select>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="12" md="6">
                    <v-select label="Comprehension"  v-model = "Comprehension" :items="scores"></v-select>
                  </v-col>
                  <v-col cols="12" md="6">
                    <v-select label="Fluency" v-model = "Fluency"  :items="scores"></v-select>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="9">

                      <v-select  label="Level"   v-if = "isSetLevel"  :readonly = "isSetLevel"  :items="levels" v-model = "Level" regular></v-select>
                      <v-select label="Level"   v-if = "!isSetLevel" :items="levels" v-model = "Level" regular></v-select>

                  </v-col>
                  <v-col cols="3">
                    <v-btn @click="UpdateLevel" v-if = "isSetLevel" class="white--text" color="#E91E63" block>Update</v-btn>

                    <v-btn @click="SaveLevel" v-if = "!isSetLevel" class="white--text" color="#E91E63" block>Save</v-btn>
                  </v-col>
                </v-row>
                <v-row>
                  <v-col cols="9">
                    <v-row>
                      <v-col cols="12">
                        <v-select  label="Curriculum"   v-if = "isSetCurriculum"  :readonly = "isSetCurriculum"  :items="curriculums" v-model = "Curriculum" regular></v-select>
                        <v-select label="Curriculum"   @change="onChangeCurriculum($event)"  v-if = "!isSetCurriculum" :items="curriculums" v-model = "Curriculum" regular></v-select>
                      </v-col>
                    </v-row>
                    <v-row>
                      <v-col cols="12">
                        <v-select  label="Material"   v-if = "isSetCurriculum"   :readonly = "isSetCurriculum" :items="books"  v-model = "Material" regular></v-select>
                        <v-select label="Material"   v-if = "!isSetCurriculum" :items="books" v-model = "Material" regular></v-select>
                      </v-col>
                    </v-row>
                  </v-col>
                  <v-col cols="3" class="mb-4 mt-2">
                    <v-btn   @click="UpdateCurriculum" v-if = "isSetCurriculum" class="white--text" color="#E91E63">Update</v-btn>
                    <v-btn   @click="SaveCurriculum" v-if = "!isSetCurriculum" class="white--text" color="#E91E63">Save</v-btn>
                  </v-col>
                </v-row>
                <v-row class="d-flex justify-content-end">
                  <v-btn text>Close</v-btn>
                  <v-btn text color="#E91E63" @click="stepper = 1">Back</v-btn>
                  <v-btn @click="stepper = 3" color="#E91E63" class="white--text">Next</v-btn>
                </v-row>
              </v-container>
            </v-stepper-content>
            <v-stepper-content step="3">
              <v-container>
                <v-row>
                  <v-col cols="12">
                    <v-textarea  v-model = "Memo" filled label="Memo"></v-textarea>
                  </v-col>
                </v-row>
                <v-row class="d-flex justify-content-end">
                  <v-btn text>Close</v-btn>
                  <v-btn text color="#E91E63" @click="stepper = 2">Back</v-btn>
                  <v-btn color="#E91E63" class="white--text" @click="addEvaluation()">Submit</v-btn>
                </v-row>
              </v-container>
            </v-stepper-content>
          </v-stepper-items>
        </v-stepper>
      </v-card>
    </v-col>
  </v-row>


</v-container>
</template>


<style scoped>
  .v-expansion-panel-header{
    padding-top: 0px;
    padding-bottom: 0px;
  }
</style>

<script>
import moment from 'moment'
import vue from 'vue'
import axios from 'axios'

export default {
  data() {
    return {
      speechSelected: '',
      speechSelected2: '',
      Tutor: [],
      Material: '',
      Curriculum: '',
      Level: '',
      EvaluationError: false,
      Class: [],
      Attendance: '',
      Pronunciation: '',
      Grammar: '',
      Comprehension: '',
      Fluency: '',
      Lesson: '',
      pageNumber: '',

      Corrected1: '',
      Corrected2: '',
      encounteredWord1: '',
      encounteredWord2: '',
      Daily1: '',
      Daily2: '',
      Memo: '',
      isSetLevel: true,
      isSetCurriculum: true,
      isSetMaterial: true,
      arrow: 'arrow_left',
      date: new Date().toISOString().substr(0, 10),
      time: new Date().toLocaleString("en-US", {
        timeZone: "Asia/Seoul"
      }).substr(11, 21),

      isMenuShowing: false,
      stepper: 1,
      tab1: null,
      tab2: null,

      word1: '',
      word2: '',
      definition1: '',
      example1: '',
      synonyms1: '',
      syn1: '',
      definition2: '',
      example2: '',
      synonyms2: '',
      loading1: false,
      loading2: false,
      transcript1: '',
      transcript2: '',
      tabArray1: [],
      tabArray2: [],

      nounArray: [],
      verbArray: [],
      adjectiveArray: [],
      adverbArray: [],
      pronounArray: [],
      prepositionArray: [],
      conjunctionArray: [],
      determinerArray: [],
      exclamationArray: [],

      nounArray2: [],
      verbArray2: [],
      adjectiveArray2: [],
      adverbArray2: [],
      pronounArray2: [],
      prepositionArray2: [],
      conjunctionArray2: [],
      determinerArray2: [],
      exclamationArray2: [],

      levelDisabled: true,
      curriculumDisabled: true,
      materialDisabled: true,

      updateLevelText: 'Update',
      updateCurriculumMaterialText: 'Update',

      attendance: ['Present', 'Absent'],

      scores: ['1', '2', '3', '4', '5', '6', '7', '8', '9'],

      levels: ['Low Beginner', 'Beginner', 'High Beginner', 'Low Intermediate',
      'Intermediate', 'High Intermediate',
      'Pre Advance', 'Advance', 'Post Advance'
    ],

    curriculums: ['Freetalking', 'Introductory Course', 'Elementary/Intermediate Conversation Course',
    'Regular Conversation', 'New York Live English', 'Grammar Pattern Course', 'Beginner Discussion',
    'Business Course', 'Specialized Job Preparation Course', 'Discussion/Free Talking Course'
  ],

  books: [],

  book_introductory_course: ['Phonics 1', 'Phonics 2', 'Phonics 3', 'Phonics 4', 'Phonics 5', 'Phonics 6',
  'Pattern Practice Junior Basic', 'Pattern Practice Junior Intermediate', 'Pattern Practice Junior Advanced',
  'Conversation Junior Basic', 'Conversation Junior Intermediate', 'Conversation Junior Advanced',
  'Advanced Phonics 1', 'Advanced Phonics 2', 'Advanced Phonics 3'
],

book_elementary_course: ['Milestones 1', 'Milestones 2', 'Milestones 3', 'First Step in Conversation 1',
'First Step in Conversation 2', 'First Step in Conversation 3'
],

book_regular_conversation: ['Conversation 1', 'Conversation 2', 'Conversation 3', 'Conversation 4', 'Conversation 5',
'Interactive English Beginner 1', 'Interactive English Beginner 2', 'Interactive English Beginner 3',
'Interactive English Intermediate 1', 'Interactive English Intermediate 2', 'Interactive English Intermediate 3',
'Interactive English Upper Intermediate 1', 'Interactive English Upper Intermediate 2', 'Interactive English Upper Intermediate 3',
'Interactive English Advanced 1', 'Interactive English Advanced 2', 'Interactive English Advanced 3'
],


book_grammar_pattern: ['Speaking Pattern Drills 1', 'Speaking Pattern Drills 2', 'Speaking Pattern Drills 4', 'Speaking Pattern Drills 5',
'Pattern Practice Adult 1', 'Pattern Practice Adult 2', 'Pattern Practice Adult 3'
],

book_beginner_discussion: ['Easy Topics for Discussion 1', 'Easy Topics for Discussion 2', 'Easy Topics for Discussion 3', 'Easy Topics for Discussion 4',
'Easy Topics for Discussion 5', "Let's Discuss 1", "Let's Discuss 2", "Let's Discuss 3", "Let's Discuss 4", "Let's Discuss 5"
],

book_business_course: ['Business English (Situational Dialogues)', 'Emailing', 'Meeting', 'Negotiation',
'Presentation', 'Business English (Discussion and Analysis)'
],

book_specialize_job_preparation_course: ['Interview', 'Hotel Dialogues', 'Cabin Crew', 'IELTS', 'Medical English',
'Tomato Opic', 'Getting Ready for TOEIC Speaking', 'Opic Advanced', 'Actual TOEIC Speaking'
],

book_discussion_course: ['English Conversation Situation Training 1', 'English Conversation Situation Training 2', 'English Conversation Situation Training 3',
'English Convesation Training Patten Drill 1', 'English Convesation Training Patten Drill 2', 'English Convesation Training Patten Drill 3',
'English Convesation Training Verb Drill 1', 'English Convesation Training Verb Drill 2', 'English Convesation Training Verb Drill 3',
'BIZ E-MAIL ENGLISH', 'BIZ TELEPHONE ENGLISH', 'BIZ PRESENTATION ENGLISH', 'BIZ MEETING DISCUSSION ENGLISH'
],

}
},

watch:{

  speechSelected(newval, oldval){


    switch(newval){

      case 'noun' :
      this.definition1 = this.nounArray[0].definition
      this.example1 = this.nounArray[0].example
      this.synonyms1 = this.nounArray[0].synonyms ?  this.nounArray[0].synonyms[0] : ''
          this.syn1 = 'test'

      console.log(this.definition1, 'def1')
        console.log( this.example1 , 'sam')
          console.log(this.synonyms1, 'syn')
          break;
      case 'verb' :
      this.definition1 = this.verbArray[0].definition
      this.example1 = this.verbArray[0].example
      this.synonyms1 = this.verbArray[0].synonyms ? this.verbArray[0].synonyms[0] : ''

        break;

      case 'adverb' :
      this.definition1 = this.adverbArray[0].definition
      this.example1 = this.adverbArray[0].example
      this.synonyms1 =   this.adverbArray[0].synonyms  ? this.adverbArray[0].synonyms[0] : ''
  break;
      case 'adjective' :
      this.definition1 = this.adjectiveArray[0].definition
      this.example1 = this.adjectiveArray[0].example
      this.synonyms1 =  this.adjectiveArray[0].synonyms  ? this.adjectiveArray[0].synonyms[0] : ''
  break;
      case 'pronoun' :
      this.definition1 = this.pronounArray[0].definition
      this.example1 = this.pronounArray[0].example
      this.synonyms1 = this.pronounArray[0].synonyms  ? this.pronounArray[0].synonyms[0] : ''
  break;
      case 'preposition' :
      this.definition1 = this.prepositionArray[0].definition
      this.example1 = this.prepositionArray[0].example
      this.synonyms1 = this.prepositionArray[0].synonyms  ? this.prepositionArray[0].synonyms[0] : ''
  break;
      case 'conjuction' :
      this.definition1 = this.conjuctionArray[0].definition
      this.example1 = this.conjuctionArray[0].example
      this.synonyms1 = this.conjuctionArray[0].synonyms  ? this.conjuctionArray[0].synonyms[0] : ''
  break;
      case 'determiner' :
      this.definition1 = this.determinerArray[0].definition
      this.example1 = this.determinerArray[0].example
      this.synonyms1 = this.determinerArray[0].synonyms  ? this.determinerArray[0].synonyms[0] : ''
  break;
      case 'exclamation' :
      this.definition1 = this.exclamationArray[0].definition
      this.example1 = this.exclamationArray[0].example
      this.synonyms1 =  this.exclamationArray[0].synonyms  ? this.exclamationArray[0].synonyms[0] : ''
  break;



default:



    }


    console.log(newval, oldval, 'val')


  },


  speechSelected2(newval, oldval){


    switch(newval){

      case 'noun' :
      this.definition2 = this.nounArray2[0].definition
      this.example2 = this.nounArray2[0].example
      this.synonyms2 = this.nounArray2[0].synonyms  ? this.nounArray2[0].synonyms[0] : ''
  break;
      console.log(this.nounArray2, 'array')

      case 'verb' :
      this.definition2 = this.verbArray2[0].definition
      this.example2 = this.verbArray2[0].example
      this.synonyms2 = this.verbArray2[0].synonyms  ? this.verbArray2[0].synonyms[0] : ''
  break;
      case 'adverb' :
      this.definition2 = this.adverbArray2[0].definition
      this.example2 = this.adverbArray2[0].example
      this.synonyms2 = this.adverbArray2[0].synonyms  ? this.adverbArray2[0].synonyms[0] : ''
  break;
      case 'adjective' :
      this.definition2 = this.adjectiveArray2[0].definition
      this.example2 = this.adjectiveArray2[0].example
      this.synonyms2 = this.adjectiveArray2[0].synonyms  ? this.adjectiveArray2[0].synonyms[0] : ''
  break;
      case 'pronoun' :
      this.definition2 = this.pronounArray2[0].definition
      this.example2 = this.pronounArray2[0].example
      this.synonyms2 = this.pronounArray2[0].synonyms  ? this.pronounArray2[0].synonyms[0] : ''
  break;
      case 'preposition' :
      this.definition2 = this.prepositionArray2[0].definition
      this.example2 = this.prepositionArray2[0].example
      this.synonyms2 =  this.prepositionArray2[0].synonyms  ?  this.prepositionArray2[0].synonyms[0] : ''

  break;
      case 'conjuction' :
      this.definition2 = this.conjuctionArray2[0].definition
      this.example2 = this.conjuctionArray2[0].example
      this.synonyms2 =  this.conjuctionArray2[0].synonyms  ?   this.conjuctionArray2[0].synonyms[0] : ''
  break;
      case 'determiner' :
      this.definition2 = this.determinerArray2[0].definition
      this.example2 = this.determinerArray2[0].example
      this.synonyms2 =  this.determinerArray2[0].synonyms  ?   this.determinerArray2[0].synonyms[0] : ''
  break;
      case 'exclamation' :
      this.definition2 = this.exclamationArray2[0].definition
      this.example2 = this.exclamationArray2[0].example
      this.synonyms2 = this.exclamationArray2[0].synonyms  ?  this.exclamationArray2[0].synonyms[0] : ''
  break;


default:
    }


    console.log(newval, oldval, 'val')


  },
},

mounted() {
  this.leftColumn = 6
  this.rightColumn = 6
  this.rightStyle = ''
  this.isMenuShowing = true
  this.arrow = 'arrow_right'

  const classId = this.$route.params.classid



  const form = new FormData();

  form.append('classId', classId)

  axios.post('Tutor/getRegularStudent', form).then(res => {


    console.log(res.data, 'data')


    if(res.data.evaluation){
      const evaluation  = JSON.parse(res.data.evaluation.evaluation)


      if(res.data.evaluation.type === 'regularclass'){




        this.Attendance = evaluation.Attendance
        this.Pronunciation = evaluation.Pronunciation
        this.Grammar = evaluation.Grammar
        this.Comprehension = evaluation.Comprehension
        this.Fluency = evaluation.Fluency
        this.Lesson = evaluation.Lesson
        this.pageNumber = evaluation.pageNumber

        this.Corrected1 = evaluation.Corrected1
        this.Corrected2 = evaluation.Corrected2
        this.word1 = evaluation.word1
        this.word2 = evaluation.word2

        this.Memo = evaluation.Memo

        this.date = evaluation.date

        this.Level = res.data.class['schedule']['level']





        this.Curriculum = res.data.class['schedule']['curriculum']

          this.onChangeCurriculum(this.Curriculum)

              this.Material  = res.data.class['schedule']['bookMaterial']










  }


  if(res.data.evaluation.type === 'leveltest'){

    this.Level = evaluation.Level





    this.Curriculum = evaluation.Curriculum

      this.onChangeCurriculum(evaluation.Curriculum)

          this.Material  = evaluation.Material

  }

      console.log(evaluation, 'eval')
    }




    this.$set(this.$data, 'Tutor', res.data.tutor)
    this.$set(this.$data, 'Class', res.data.class)



    this.showMenu()



    console.log(res.data, 'data')

  })
},

methods: {

  showMenu() {

    if (!this.isMenuShowing) {
      this.leftColumn = 6
      this.rightColumn = 6
      this.rightStyle = ''
      this.isMenuShowing = true
      this.arrow = 'arrow_right'
    } else {
      this.leftColumn = 12
      this.rightColumn = 0
      this.rightStyle = 'display:none'
      this.isMenuShowing = false
      this.arrow = 'arrow_left'
    }
  },

  updateLevel(event) {
    if (event.target.innerText == 'UPDATE') {
      this.levelDisabled = false
      this.updateLevelText = 'SAVE'
    } else {
      this.levelDisabled = true
      this.updateLevelText = 'UPDATE'
    }
  },

  updateCurriculumMaterial(event) {
    if (event.target.innerText == 'UPDATE') {
      this.curriculumDisabled = false
      this.materialDisabled = false
      this.updateCurriculumMaterialText = 'SAVE'
    } else {
      this.curriculumDisabled = true
      this.materialDisabled = true
      this.updateCurriculumMaterialText = 'UPDATE'
    }
  },


  onChangeCurriculum(event) {
    if (event == 'Freetalking') {
      vue.set(this.$data, 'books', [])
    } else if (event == 'Introductory Course') {
      vue.set(this.$data, 'books', this.$data.book_introductory_course)
    } else if (event == 'Elementary/Intermediate Conversation Course') {
      vue.set(this.$data, 'books', this.$data.book_elementary_course)
    } else if (event == 'Regular Conversation') {
      vue.set(this.$data, 'books', this.$data.book_regular_conversation)
    } else if (event == 'New York Live English') {
      vue.set(this.$data, 'books', [])
    } else if (event == 'Grammar Pattern Course') {
      vue.set(this.$data, 'books', this.$data.book_grammar_pattern)
    } else if (event == 'Beginner Discussion') {
      vue.set(this.$data, 'books', this.$data.book_beginner_discussion)
    } else if (event == 'Business Course') {
      vue.set(this.$data, 'books', this.$data.book_business_course)
    } else if (event == 'Specialized Job Preparation Course') {
      vue.set(this.$data, 'books', this.$data.book_specialize_job_preparation_course)
    } else if (event == 'Discussion/Free Talking Course') {
      vue.set(this.$data, 'books', this.$data.book_discussion_course)
    }
  },


  getDefinition1() {
    const proxy = "https://cors-anywhere.herokuapp.com/"
    const URL = 'https://api.dictionaryapi.dev/api/v2/entries/en/' + this.word1

    this.loading1 = true
    axios.get(proxy + URL).then((response) => {
      this.loading1 = false

      this.tabArray1 = []
      this.nounArray = []
      this.verbArray = []
      this.adjectiveArray = []
      this.adverbArray = []
      this.pronounArray = []
      this.prepositionArray = []
      this.conjunctionArray = []
      this.determinerArray = []
      this.exclamationArray = []

      this.transcript1 = response.data[0]['phonetic']

      for (let i = 0; i < response.data.length; i++) {

        for (let j = 0; j < response.data[i]['meanings'].length; j++) {


          var partOfSpeech = response.data[i]['meanings'][j]['partOfSpeech']
          var definitions = response.data[i]['meanings'][j]['definitions']

          if (this.tabArray1.indexOf(partOfSpeech) == -1) {

            if (partOfSpeech.indexOf('verb') != -1 && partOfSpeech != 'adverb') {
              this.tabArray1.push('verb')
            } else {
              this.tabArray1.push(partOfSpeech)
            }

          }

          if (partOfSpeech == 'noun') {
            for (let x = 0; x < definitions.length; x++) {
              this.nounArray.push(definitions[x])
            }
          }
          if (partOfSpeech.indexOf('verb') != -1 && partOfSpeech != 'adverb') {
            for (let x = 0; x < definitions.length; x++) {
              this.verbArray.push(definitions[x])
            }
          }
          if (partOfSpeech == 'pronoun') {
            for (let x = 0; x < definitions.length; x++) {
              this.pronounArray.push(definitions[x])
            }
          }
          if (partOfSpeech == 'adjective') {
            for (let x = 0; x < definitions.length; x++) {
              this.adjectiveArray.push(definitions[x])
            }
          }
          if (partOfSpeech == 'adverb') {
            for (let x = 0; x < definitions.length; x++) {
              this.adverbArray.push(definitions[x])

            }
          }
          if (partOfSpeech == 'preposition') {
            for (let x = 0; x < definitions.length; x++) {
              this.prepositionArray.push(definitions[x])
            }
          }
          if (partOfSpeech == 'conjunction') {
            for (let x = 0; x < definitions.length; x++) {
              this.conjunctionArray.push(definitions[x])
            }
          }
          if (partOfSpeech == 'determiner') {
            for (let x = 0; x < definitions.length; x++) {
              this.determinerArray.push(definitions[x])
            }
          }
          if (partOfSpeech == 'exclamation') {
            for (let x = 0; x < definitions.length; x++) {
              this.exclamationArray.push(definitions[x])
            }
          }
        }

      }

      console.log(this.adverbArray)

    })
  },

  getDefinition2() {
    const proxy = "https://cors-anywhere.herokuapp.com/"
    const URL = 'https://api.dictionaryapi.dev/api/v2/entries/en/' + this.word2

    this.loading2 = true
    axios.get(proxy + URL).then((response) => {
      this.loading2 = false

      this.tabArray2 = []
      this.nounArray = []
      this.verbArray = []
      this.adjectiveArray = []
      this.adverbArray = []
      this.pronounArray = []
      this.prepositionArray = []
      this.conjunctionArray = []
      this.determinerArray = []
      this.exclamationArray = []

      this.transcript2 = response.data[0]['phonetic']

      for (let i = 0; i < response.data.length; i++) {

        for (let j = 0; j < response.data[i]['meanings'].length; j++) {


          var partOfSpeech = response.data[i]['meanings'][j]['partOfSpeech']
          var definitions = response.data[i]['meanings'][j]['definitions']

          if (this.tabArray2.indexOf(partOfSpeech) == -1) {

            if (partOfSpeech.indexOf('verb') != -1 && partOfSpeech != 'adverb') {
              this.tabArray2.push('verb')
            } else {
              this.tabArray2.push(partOfSpeech)
            }

          }

          if (partOfSpeech == 'noun') {
            for (let x = 0; x < definitions.length; x++) {
              this.nounArray2.push(definitions[x])
            }
          }
          if (partOfSpeech.indexOf('verb') != -1 && partOfSpeech != 'adverb') {
            for (let x = 0; x < definitions.length; x++) {
              this.verbArray2.push(definitions[x])
            }
          }
          if (partOfSpeech == 'pronoun') {
            for (let x = 0; x < definitions.length; x++) {
              this.pronounArray2.push(definitions[x])
            }
          }
          if (partOfSpeech == 'adjective') {
            for (let x = 0; x < definitions.length; x++) {
              this.adjectiveArray2.push(definitions[x])
            }
          }
          if (partOfSpeech == 'adverb') {
            for (let x = 0; x < definitions.length; x++) {
              this.adverbArray2.push(definitions[x])
            }
          }
          if (partOfSpeech == 'preposition') {
            for (let x = 0; x < definitions.length; x++) {
              this.prepositionArray2.push(definitions[x])
            }
          }
          if (partOfSpeech == 'conjunction') {
            for (let x = 0; x < definitions.length; x++) {
              this.conjunctionArray2.push(definitions[x])
            }
          }
          if (partOfSpeech == 'determiner') {
            for (let x = 0; x < definitions.length; x++) {
              this.determinerArray2.push(definitions[x])
            }
          }
          if (partOfSpeech == 'exclamation') {
            for (let x = 0; x < definitions.length; x++) {
              this.exclamationArray2.push(definitions[x])
            }
          }
        }

      }

      console.log(this.tabArray2)

    })
  },


  getEndContract(){


  let class_end_schedule = this.Class['schedule']['class_end'].split(",")

  let end_schedule =  class_end_schedule[class_end_schedule.length-1]

  return end_schedule.split(" ")[0]




},

getApplicableDays(){

  return this.Class['schedule']['applicable_days'].substr(0,this.Class['schedule']['applicable_days'].length -1 ).substr(1)
},

getHour(){

  return moment({hour: this.Class['schedule']['hour'], minute:this.Class['schedule']['minute']}).format('HH:mm:ss')


},

UpdateLevel(){

  if(this.isSetLevel === true){

    this.isSetLevel = false
  }
},

 async SaveLevel(){


      const data = prompt('Enter classid for confirmation')

      console.log( this.Class['schedule']['classid'], 'id')
      if(data === this.Class['schedule']['classid'] && this.Level){

        const classid = this.Class['schedule']['classid']
        const form = new FormData()
        form.append('classid', classid)
        form.append('Level', this.Level)
        axios.post('Tutor/saveLevel', form).then(res => {

          console.log(res.data)
        })
      }

},


UpdateCurriculum(){

  if(this.isSetCurriculum === true){

    this.isSetCurriculum = false
  }
},

 async SaveCurriculum(){


   const data = prompt('Enter classid for confirmation')


   if(data === this.Class['schedule']['classid'] && this.Curriculum && this.Material){

     const classid = this.Class['schedule']['classid']
     const form = new FormData()
     form.append('classid', classid)
     form.append('Curriculum', this.Curriculum)
     form.append('Material', this.Material)

     axios.post('Tutor/SaveCurriculum', form).then(res => {

       console.log(res.data)
     })
   }

},




addEvaluation(){

console.log('test', this.synonyms1, 'wes')
const studentname = this.Class['schedule']['name']
const tutorname = this.Tutor['mega_name']
const tutoridx = this.Tutor['idx']
const classid =  this.Class['schedule']['classid']
const phone_number = this.Class['schedule']['phone_number']

console.log(studentname, 'studentname')
console.log(this.Curriculum, 'curri')
console.log(this.Material, 'ma')
console.log(this.Level, 'lev')
console.log(classid, 'cl')



const Lesson = this.Lesson

const pageNumber = this.pageNumber
const Attendance = this.Attendance




const Evaluation = {Lesson:Lesson, pageNumber: pageNumber, Attendance: Attendance , Pronunciation: this.Pronunciation, Grammar: this.Grammar, Comprehension: this.Comprehension, Fluency: this.Fluency, Corrected1: this.Corrected1, Corrected2: this.Corrected2, word1: this.word1, word2: this.word2,  Memo: this.Memo, date: moment().format('YYYY-MM-DD'), tutorName: tutorname, tutorIdx: tutoridx, classid: classid}

console.log('evaluation', Evaluation)
const checkObj =  Object.values(Evaluation).some(data => (data === null || data === ''))


Evaluation.transcript1 = this.transcript1
Evaluation.transcript2 = this.transcript2
Evaluation.definition1 = JSON.stringify(this.definition1)
Evaluation.example1 = JSON.stringify(this.example1)
Evaluation.synonyms1 = this.synonyms1
Evaluation.definition2 = JSON.stringify(this.definition2)
Evaluation.example2 = JSON.stringify(this.example2)
Evaluation.synonyms2 = this.synonyms2
if(checkObj === true || !this.Level || !this.Curriculum || !this.Material || !studentname || !classid ){

  this.EvaluationError = true
  this.$vuetify.goTo(0)
}

else{
const form = new FormData()
form.append('evaluation', JSON.stringify(Evaluation))
form.append('studentname', studentname)
form.append('classid', classid)
form.append('phone_number', phone_number)


axios.post('Evaluation/addEvaluation', form).then(res => {


  if(res.data.error === false){

    window.close()
  }

  console.log(res.data, 'data')
}).catch(err => {

  console.log(err, 'err')
})

}



}


},
}
</script>

<style lang="css">
</style>
